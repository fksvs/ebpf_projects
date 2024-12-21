#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("tp/syscalls/sys_enter_execve")
int handle_execve(void *ctx)
{
	int pid = bpf_get_current_pid_tgid() >> 32;
	
	bpf_printk("[sys_enter_execve] PID : %d\n", pid);

	return 0;
}
