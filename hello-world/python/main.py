#!/usr/bin/python

from bcc import BPF

BPF_PROGRAM = """
int on_syscall_execve(void* ctx) {
  bpf_trace_printk("Hello world by execve call.\\n");
  return 0;
}
"""

bpf = BPF(text = BPF_PROGRAM)
fnname = bpf.get_syscall_fnname("execve")
bpf.attach_kprobe(event = fnname, fn_name = "on_syscall_execve")
bpf.trace_print()
