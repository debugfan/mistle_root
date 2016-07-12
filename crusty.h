#ifndef CRUSTY_H
#define CRUSTY_H

#ifdef __arm__

struct thread_info {
  unsigned long flags;
  int preempt_count;
  unsigned long addr_limit;
  struct task_struct *task;

  /* ... */
};

#elif defined(__i386__)

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
#error No specified arch
#endif


#endif
