#include <uapi/linux/ptrace.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>
#include <bcc/proto.h>

// Define storage for tracking start times and latencies
BPF_HASH(read_start, u32, u64);  // Thread ID -> read start timestamp
BPF_HASH(write_start, u32, u64); // Thread ID -> write start timestamp
BPF_HISTOGRAM(read_latency_us);  // Histogram for read latencies
BPF_HISTOGRAM(write_latency_us); // Histogram for write latencies

// Helper macro to get PID namespace inode number
#define GET_PID_NS_INUM \
    ((struct task_struct *)bpf_get_current_task())->nsproxy->pid_ns_for_children->ns.inum

// Track start time for overlayfs read operations
KPROBE(ovl_read_iter, struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid() >> 32;
    u64 ts = bpf_ktime_get_ns();
    u32 inum = $1; // PID namespace inode number from command line

    // Filter by PID namespace
    if (GET_PID_NS_INUM != inum)
        return 0;

    read_start.update(&tid, &ts);
    return 0;
}

// Measure and record latency for overlayfs read operations
KRETPROBE(ovl_read_iter, struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid() >> 32;
    u32 inum = $1;
    
    // Filter by PID namespace
    if (GET_PID_NS_INUM != inum)
        return 0;

    // Get start time
    u64 *ts = read_start.lookup(&tid);
    if (ts == NULL)
        return 0;

    // Calculate latency in microseconds
    u64 duration_us = (bpf_ktime_get_ns() - *ts) / 1000;
    read_latency_us.increment(bpf_log2l(duration_us));

    // Clean up
    read_start.delete(&tid);
    return 0;
}

// Track start time for overlayfs write operations
KPROBE(ovl_write_iter, struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid() >> 32;
    u64 ts = bpf_ktime_get_ns();
    u32 inum = $1;

    // Filter by PID namespace
    if (GET_PID_NS_INUM != inum)
        return 0;

    write_start.update(&tid, &ts);
    return 0;
}

// Measure and record latency for overlayfs write operations
KRETPROBE(ovl_write_iter, struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid() >> 32;
    u32 inum = $1;

    // Filter by PID namespace
    if (GET_PID_NS_INUM != inum)
        return 0;

    // Get start time
    u64 *ts = write_start.lookup(&tid);
    if (ts == NULL)
        return 0;

    // Calculate latency in microseconds
    u64 duration_us = (bpf_ktime_get_ns() - *ts) / 1000;
    write_latency_us.increment(bpf_log2l(duration_us));

    // Clean up
    write_start.delete(&tid);
    return 0;
}

// Periodically print latency histograms
INTERVAL(1000) {
    // Print timestamp
    bpf_trace_printk("\n%T --------------------\n");

    // Print histograms
    bpf_trace_printk("Write Latency (us):\n");
    write_latency_us.print_log2_hist();
    bpf_trace_printk("Read Latency (us):\n");
    read_latency_us.print_log2_hist();

    // Clear histograms for next interval
    write_latency_us.clear();
    read_latency_us.clear();
}

// Cleanup on program exit
END {
    read_start.clear();
    write_start.clear();
    read_latency_us.clear();
    write_latency_us.clear();
}
