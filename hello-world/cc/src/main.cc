
#include <bcc/BPF.h>

#include <fstream>
#include <iostream>
#include <string>

const std::string BPF_PROGRAM = R"(
int on_syscall_execve(void* ctx) {
  bpf_trace_printk("Hello world by execve call.\n");
  return 0;
}
)";

int main() {
  ebpf::BPF bpf;
  auto init_res = bpf.init(BPF_PROGRAM);
  if (init_res.code() != 0) {
    std::cerr << init_res.msg() << std::endl;
    return 1;
  }

  auto fnname = bpf.get_syscall_fnname("execve");
  auto attach_res = bpf.attach_kprobe(fnname, "on_syscall_execve");
  if (init_res.code() != 0) {
    std::cerr << attach_res.msg() << std::endl;
    return 1;
  }

  std::ifstream pipe("/sys/kernel/debug/tracing/trace_pipe");
  while (true) {
    std::string line;
    if (std::getline(pipe, line)) {
      std::cout << line << std::endl;
      auto detach_res = bpf.detach_kprobe(fnname);
      if (init_res.code() != 0) {
        std::cerr << detach_res.msg() << std::endl;
        return 1;
      }
      break;
    } else {
      std::cout << "Waiting for an event." << std::endl;
      sleep(1);
    }
  }

  return 0;
}
