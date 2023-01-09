// This program demonstrates attaching an eBPF program to a kernel symbol.
// The eBPF program will be attached to the start of the sys_execve
// kernel function and prints out the number of times it has been called
// every second.
package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS --target=amd64 bpf main.c -- -I../headers

const mapKey uint32 = 0

func main() {

	// 将要trace的内核函数名称
	fn := "do_sys_openat2"

	// Allow the current process to lock memory for eBPF resources.
	// 允许当前进程去锁定eBPF资源的内存占用
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	// 加载 编译好的BPF程序和map 到内核中
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Open a Kprobe at the entry point of the kernel function and attach the
	// pre-compiled program. Each time the kernel function enters, the program
	// will increment the execution counter by 1. The read loop below polls this
	// map value once per second.
	// 打开内核函数的入口kprobe，将编译好的BPF程序放置在kprobe,每次进入这个内核函数入口的时候执行BPF代码
	kp, err := link.Kprobe(fn, objs.KprobeOpenat2, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp.Close()

	// 循环读取 /sys/kernel/debug/tracing/trace_pipe 文件
	f, _ := os.OpenFile("/sys/kernel/debug/tracing/trace_pipe", os.O_RDONLY, os.ModePerm)
	defer f.Close()
	reader := bufio.NewReader(f)
	for {
		line, _, err := reader.ReadLine()
		if err == io.EOF {
			break
		}
		fmt.Println(string(line))
	}
}
