// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Sartura */
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1024);
} rb SEC(".maps");

struct event {
  int pid;
};

SEC("kprobe/do_unlinkat")
int BPF_KPROBE(do_unlinkat, int dfd, struct filename *name) {
  pid_t pid;
  const char *filename;

  pid = bpf_get_current_pid_tgid() >> 32;
  filename = BPF_CORE_READ(name, name);
  bpf_printk("KPROBE ENTRY pid = %d, filename = %s\n", pid, filename);
  struct event *e;

  e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
  if (!e)  {
    return 0;
  }

  e->pid = pid;
  bpf_ringbuf_submit(e, 0);

  return 0;
}

SEC("kretprobe/do_unlinkat")
int BPF_KRETPROBE(do_unlinkat_exit, long ret) {
  pid_t pid;
  struct event *e;

  pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("KPROBE EXIT: pid = %d, ret = %ld\n", pid, ret);
  
  e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
  if (!e) {
    return 0;
  }

  e->pid = pid;
  bpf_ringbuf_submit(e, 0);

  return 0;
}