// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * Floatie - eBPF-powered container monitoring tool
 * 
 * OOM Kill monitoring functionality using eBPF
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

package ebpf

import (
	"context"
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/yourusername/floatie/pkg/metrics"
)

//go:generate bpf2go -cc clang -target bpfel -type oom_event OOMKill ../../../bpf/oomkill.bpf.c -- -I/usr/include -I.

// OOMKillMonitor represents an active OOM Kill monitoring session
type OOMKillMonitor struct {
	objs      OOMKillObjects
	kprobe    link.Link
	reader    *ringbuf.Reader
	closeChan chan struct{}
}

// StartOOMKillMonitoring starts monitoring OOM kill events
func StartOOMKillMonitoring(ctx context.Context, pidNsInum, maxMapEntries uint32) (*OOMKillMonitor, error) {
	// Load eBPF programs with custom map sizes
	spec, err := LoadOOMKill()
	if err != nil {
		return nil, fmt.Errorf("failed to load OOMKill spec: %w", err)
	}
	
	// Set map sizes
	for _, m := range spec.Maps {
		if m.MaxEntries == 0 {
			m.MaxEntries = maxMapEntries
		}
	}
	
	var objs OOMKillObjects
	if err := spec.LoadAndAssign(&objs, &ebpf.CollectionOptions{}); err != nil {
		return nil, fmt.Errorf("failed to load OOMKill objects: %w", err)
	}
	
	// Attach kprobe
	kp, err := link.Kprobe("oom_kill_process", objs.OomKillProcess, nil)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("failed to attach oom_kill_process kprobe: %w", err)
	}
	
	// Create ring buffer reader
	reader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		kp.Close()
		objs.Close()
		return nil, fmt.Errorf("failed to create ring buffer reader: %w", err)
	}
	
	monitor := &OOMKillMonitor{
		objs:      objs,
		kprobe:    kp,
		reader:    reader,
		closeChan: make(chan struct{}),
	}
	
	// Start processing events
	go monitor.processEvents(ctx)
	
	return monitor, nil
}

// processEvents reads events from the ring buffer and updates metrics
func (m *OOMKillMonitor) processEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.closeChan:
			return
		default:
			record, err := m.reader.Read()
			if err != nil {
				if err == ringbuf.ErrClosed {
					return
				}
				log.Printf("Error reading from ring buffer: %v", err)
				continue
			}
			
			var event OomEvent
			if err := ringbuf.Unmarshal(record.RawSample, &event); err != nil {
				log.Printf("Error parsing OOM event: %v", err)
				continue
			}
			
			triggerComm := nullTerminatedString(event.TriggerComm[:])
			victimComm := nullTerminatedString(event.VictimComm[:])
			
			metrics.OOMKillsCounter.WithLabelValues(triggerComm, victimComm).Inc()
			
			log.Printf("OOM Kill: Trigger PID %d (%s), Victim PID %d (%s), Total Pages %d",
				event.TriggerPid, triggerComm, event.VictimPid, victimComm, event.TotalPages)
				
			// Update memory pressure gauge based on OOM kill occurrences
			// This is a simple heuristic and could be refined
			metrics.MemPressureGauge.Set(80.0) // High value as OOM occurred
		}
	}
}

// Close cleans up resources used by the OOM kill monitor
func (m *OOMKillMonitor) Close() error {
	close(m.closeChan)
	
	if m.reader != nil {
		m.reader.Close()
	}
	
	if m.kprobe != nil {
		m.kprobe.Close()
	}
	
	return m.objs.Close()
}

// nullTerminatedString converts a byte array to a string, stopping at null byte
func nullTerminatedString(data []byte) string {
	for i, b := range data {
		if b == 0 {
			return string(data[:i])
		}
	}
	return string(data)
}