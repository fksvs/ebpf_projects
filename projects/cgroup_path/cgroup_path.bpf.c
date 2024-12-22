#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_PATH 4096

struct proc_info {
	int pid;
	int uid;
	int cgroup_id;
	char comm[TASK_COMM_LEN];
	char cgroup_path[MAX_PATH];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct proc_info);
	__uint(max_entries, 1);
} proc_info_map SEC(".maps");

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("tp/syscalls/sys_enter_execve")
int cgroup_path(void *ctx)
{
	struct proc_info *proc;
	int key = 0;

	proc = bpf_map_lookup_elem(&proc_info_map, &key);
	if (!proc) {
		bpf_printk("[sys_enter_execve] [ERROR] : cannot find map slot\n");
		return -1;
	}

	proc->pid = bpf_get_current_pid_tgid() >> 32;
	proc->uid = bpf_get_current_uid_gid() >> 32;
	proc->cgroup_id = bpf_get_current_cgroup_id();

	if (bpf_get_current_comm(proc->comm, TASK_COMM_LEN) < 0) {
		bpf_printk("[sys_enter_execve] [ERROR] : cannot read command\n");
		return -1;
	}

	struct task_struct *tsp = (struct task_struct *)bpf_get_current_task();
	if (tsp == NULL) {
		bpf_printk("[sys_enter_execve] [ERROR] : cannot read task_struct\n");
		return -1;
	}

	const char *name = BPF_CORE_READ(tsp, cgroups, subsys[0], cgroup, kn, name);
	if (bpf_probe_read_kernel_str(proc->cgroup_path, MAX_PATH, name) < 0) {
		bpf_printk("[sys_enter_execve] [ERROR] : cannot read cgroup path\n");
		return -1;
	}

	bpf_printk("pid : %d uid : %d cgroupid : %d command : %s cgroup path : %s",
			proc->pid, proc->uid, proc->cgroup_id,
			proc->comm, proc->cgroup_path);

	return 0;
}
