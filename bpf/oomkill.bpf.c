// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * Floatie - eBPF-powered container monitoring tool
 * 
 * OOM Kill monitoring eBPF program
 *
 * Copyright (C) 2025 Justin Johns
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <uapi/linux/ptrace.h>
#include <linux/oom.h>
#include <linux/sched.h>
#include <bcc/proto.h>

// BPF program to trace OOM killer events with optimized data collection
BPF_PERF_OUTPUT(events);

// Structure to hold OOM event data
struct oom_event {
    u32 trigger_pid;        // PID that triggered OOM
    u32 victim_pid;        // PID of process chosen for termination
    char trigger_comm[16];  // Command name of triggering process
    char victim_comm[16];   // Command name of victim process
    u64 total_pages;       // Total pages considered for OOM
    u32 load_avg[3];       // System load averages (1, 5, 15 minutes)
    u64 timestamp;         // Event timestamp
};

// Helper to read load averages from /proc/loadavg
static inline void get_load_avg(u32 *load_avg) {
    char buf[64];
    u64 addr = (u64)&buf;
    u32 i;

    // Read /proc/loadavg directly in kernel space
    if (bpf_probe_read_kernel_str(buf, sizeof(buf), "/proc/loadavg") > 0) {
        // Parse first three load average values (scaled by 100)
        u32 val = 0;
        u8 pos = 0;
        for (i = 0; i < sizeof(buf) && pos < 3; i++) {
            if (buf[i] >= '0' && buf[i] <= '9') {
                val = val * 10 + (buf[i] - '0');
            } else if (buf[i] == '.' || buf[i] == ' ') {
                if (buf[i] == ' ') {
                    load_avg[pos++] = val;
                    val = 0;
                }
            }
        }
    }
}

// Trace oom_kill_process kernel function
KPROBE(oom_kill_process, struct pt_regs *ctx) {
    struct oom_control *oc = (struct oom_control *)PT_REGS_PARM2(ctx);
    struct oom_event evt = {0};
    struct task_struct *chosen;

    // Read chosen task safely
    if (bpf_probe_read_kernel(&chosen, sizeof(chosen), &oc->chosen))
        return 0;

    // Skip if no process was chosen
    if (!chosen)
        return 0;

    // Populate event data
    evt.timestamp = bpf_ktime_get_ns();
    evt.trigger_pid = bpf_get_current_pid_tgid() >> 32;
    evt.victim_pid = chosen->pid;
    evt.total_pages = oc->totalpages;

    // Get process names
    bpf_get_current_comm(&evt.trigger_comm, sizeof(evt.trigger_comm));
    bpf_probe_read_kernel_str(&evt.victim_comm, sizeof(evt.victim_comm), chosen->comm);

    // Read load averages
    get_load_avg(evt.load_avg);

    // Submit event to user space
    events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

// Program initialization
BEGIN {
    bpf_trace_printk("Tracing oom_kill_process()... Hit Ctrl-C to end.\n");
}
