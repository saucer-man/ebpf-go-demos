// +build ignore

#include "common.h"
#include "bpf_tracing.h"
char __license[] SEC("license") = "Dual MIT/GPL";


SEC("kprobe/do_sys_openat2")
int kprobe_openat2(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32; // 得到当前进程的pid
	char filename[20];
	const char *fp = (char *)PT_REGS_PARM2(ctx);
	long err = bpf_probe_read_user_str(filename, sizeof(filename), fp);
	bpf_printk("pid:%d,filename:%s,err:%ld",pid,filename,err);

	return 0;
}
