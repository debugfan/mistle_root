#ifndef CRUSTY_H
#define CRUSTY_H

#include <stdio.h>
#include <stdlib.h>

#define THREAD_SIZE             8192
#define KERNEL_START            0xc0000000

struct list_head {
  struct list_head *next;
  struct list_head *prev;
};

struct kernel_cap_struct {
  unsigned long cap[2];
};

struct task_security_struct {
  unsigned long osid;
  unsigned long sid;
  unsigned long exec_sid;
  unsigned long create_sid;
  unsigned long keycreate_sid;
  unsigned long sockcreate_sid;
};

#ifdef __arm__

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

struct task_struct_partial {
  struct list_head cpu_timers[3];
  struct cred *real_cred;
  struct cred *cred;
  struct cred *replacement_session_keyring;
  char comm[16];
};

struct thread_info {
  unsigned long flags;
  int preempt_count;
  unsigned long addr_limit;
  struct task_struct *task;

  /* ... */
};

#elif defined(__i386__)

typedef unsigned int __u32;

struct cred {
	//atomic_t	usage;
    unsigned long	usage;
	uid_t		uid;		/* real UID of the task */
	gid_t		gid;		/* real GID of the task */
	uid_t		suid;		/* saved UID of the task */
	gid_t		sgid;		/* saved GID of the task */
	uid_t		euid;		/* effective UID of the task */
	gid_t		egid;		/* effective GID of the task */
	uid_t		fsuid;		/* UID for VFS ops */
	gid_t		fsgid;		/* GID for VFS ops */
	unsigned	securebits;	/* SUID-less security management */
	struct kernel_cap_struct	cap_inheritable; /* caps our children can inherit */
	struct kernel_cap_struct	cap_permitted;	/* caps we're permitted */
	struct kernel_cap_struct	cap_effective;	/* caps we can actually use */
	struct kernel_cap_struct	cap_bset;	/* capability bounding set */
//#ifdef CONFIG_KEYS
	unsigned char	jit_keyring;	/* default keyring to attach requested
					 * keys to */
	void    *session_keyring; /* keyring inherited over fork */
	void	*process_keyring; /* keyring private to this process */
	void	*thread_keyring; /* keyring private to this thread */
	void	*request_key_auth; /* assumed request_key authority */
//#endif
//#ifdef CONFIG_SECURITY
//	void		*security;	/* subjective LSM security */
    struct task_security_struct *security;
//#endif
    
	//struct user_struct *user;	/* real user ID subscription */
	//struct user_namespace *user_ns; /* user_ns the caps and keyrings are relative to. */
	//struct group_info *group_info;	/* supplementary groups for euid/fsgid */
	//struct rcu_head	rcu;		/* RCU deletion hook */
};

struct task_struct_partial {
  struct list_head cpu_timers[3];
  struct cred *real_cred;
  struct cred *cred;
  char comm[16];
};

struct thread_info {
    struct task_struct  *task;      /* main task structure */
    struct exec_domain  *exec_domain;   /* execution domain */
    __u32           flags;      /* low level flags */
    __u32           status;     /* thread synchronous flags */
    __u32           cpu;        /* current CPU */
    int         preempt_count;  /* 0 => preemptable,
                           <0 => BUG */
    unsigned long  addr_limit;

    /* ... */
};

#else
#error No specified arch found
#endif


#endif
