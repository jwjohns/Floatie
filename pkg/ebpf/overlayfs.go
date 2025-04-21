// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * Floatie - eBPF-powered container monitoring tool
 * 
 * OverlayFS latency monitoring functionality using eBPF
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
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/yourusername/floatie/pkg/metrics"
)

//go:generate bpf2go -cc clang -target bpfel OverlayFS ../../../bpf/overlayfs_latency.bpf.c -- -I/usr/include -I.

// OverlayFSMonitor represents an active OverlayFS monitoring session
type OverlayFSMonitor struct {
	objs           OverlayFSObjects
	readKprobe     link.Link
	readKretprobe  link.Link
	writeKprobe    link.Link
	writeKretprobe link.Link
	ticker         *time.Ticker
	stopChan       chan struct{}
}

// StartOverlayFSMonitoring starts monitoring OverlayFS latency
func StartOverlayFSMonitoring(ctx context.Context, pidNsInum, maxMapEntries uint32) (*OverlayFSMonitor, error) {
	// Load eBPF programs with custom map sizes
	spec, err := LoadOverlayFS()
	if err != nil {
		return nil, fmt.Errorf("failed to load OverlayFS spec: %w", err)
	}
	
	// Set map sizes
	for _, m := range spec.Maps {
		if m.MaxEntries == 0 {
			m.MaxEntries = maxMapEntries
		}
	}
	
	var objs OverlayFSObjects
	opts := ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			// Set the PID namespace inode number via the '$1' variable in eBPF program
			ProgramContext: map[string]interface{}{
				"$1": pidNsInum,
			},
		},
	}
	
	if err := spec.LoadAndAssign(&objs, &opts); err != nil {
		return nil, fmt.Errorf("failed to load OverlayFS objects: %w", err)
	}

	// Attach kprobes and kretprobes with retry logic
	readKprobe, err := attachProbe("ovl_read_iter", objs.OvlReadIter, link.Kprobe)
	if err != nil {
		objs.Close()
		return nil, err
	}

	readKretprobe, err := attachProbe("ovl_read_iter", objs.OvlReadIter, link.Kretprobe)
	if err != nil {
		readKprobe.Close()
		objs.Close()
		return nil, err
	}

	writeKprobe, err := attachProbe("ovl_write_iter", objs.OvlWriteIter, link.Kprobe)
	if err != nil {
		readKprobe.Close()
		readKretprobe.Close()
		objs.Close()
		return nil, err
	}

	writeKretprobe, err := attachProbe("ovl_write_iter", objs.OvlWriteIter, link.Kretprobe)
	if err != nil {
		readKprobe.Close()
		readKretprobe.Close()
		writeKprobe.Close()
		objs.Close()
		return nil, err
	}

	monitor := &OverlayFSMonitor{
		objs:           objs,
		readKprobe:     readKprobe,
		readKretprobe:  readKretprobe,
		writeKprobe:    writeKprobe,
		writeKretprobe: writeKretprobe,
		ticker:         time.NewTicker(1 * time.Second),
		stopChan:       make(chan struct{}),
	}
	
	// Start processing events
	go monitor.processHistograms(ctx)
	
	return monitor, nil
}

// attachProbe attaches a kernel probe with retry logic
func attachProbe(symbol string, prog *ebpf.Program, attachFn func(string, *ebpf.Program, *link.KprobeOptions) (link.Link, error)) (link.Link, error) {
	var l link.Link
	var err error
	
	for i := 0; i < 3; i++ {
		l, err = attachFn(symbol, prog, nil)
		if err == nil {
			return l, nil
		}
		log.Printf("Retrying attach for %s: %v", symbol, err)
		time.Sleep(time.Second)
	}
	
	return nil, fmt.Errorf("failed to attach %s after retries: %w", symbol, err)
}

// processHistograms periodically reads histogram data and updates Prometheus metrics
func (m *OverlayFSMonitor) processHistograms(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopChan:
			return
		case <-m.ticker.C:
			// Process read_latency_us
			if err := m.processLatencyHistogram(m.objs.ReadLatencyUs, metrics.ReadLatencyHist); err != nil {
				log.Printf("Error processing read latency histogram: %v", err)
			}
			
			// Process write_latency_us
			if err := m.processLatencyHistogram(m.objs.WriteLatencyUs, metrics.WriteLatencyHist); err != nil {
				log.Printf("Error processing write latency histogram: %v", err)
			}
		}
	}
}

// processLatencyHistogram reads from eBPF histogram and updates Prometheus metric
func (m *OverlayFSMonitor) processLatencyHistogram(bpfHist *ebpf.Map, promHist prometheus.Histogram) error {
	var (
		slot  uint64
		count uint64
	)
	
	iter := bpfHist.Iterate()
	for iter.Next(&slot, &count) {
		if count > 0 {
			latencyUs := float64(1 << slot) // Convert log2 value to microseconds
			for i := uint64(0); i < count; i++ {
				promHist.Observe(latencyUs)
			}
		}
	}
	
	return iter.Err()
}

// Close cleans up resources used by the OverlayFS monitor
func (m *OverlayFSMonitor) Close() error {
	m.ticker.Stop()
	close(m.stopChan)
	
	if m.readKprobe != nil {
		m.readKprobe.Close()
	}
	
	if m.readKretprobe != nil {
		m.readKretprobe.Close()
	}
	
	if m.writeKprobe != nil {
		m.writeKprobe.Close()
	}
	
	if m.writeKretprobe != nil {
		m.writeKretprobe.Close()
	}
	
	return m.objs.Close()
}