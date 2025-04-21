// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * Floatie - eBPF-powered container monitoring tool
 * 
 * Prometheus metrics registration and definitions
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

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	// Read latency metrics
	ReadLatencyHist = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "floatie_overlayfs_read_latency_us",
		Help:    "OverlayFS read latency in microseconds",
		Buckets: prometheus.ExponentialBuckets(1, 2, 20), // Cover from 1µs to ~1s
	})

	// Write latency metrics
	WriteLatencyHist = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "floatie_overlayfs_write_latency_us",
		Help:    "OverlayFS write latency in microseconds",
		Buckets: prometheus.ExponentialBuckets(1, 2, 20),
	})

	// OOM kill metrics
	OOMKillsCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "floatie_oom_kills_total",
		Help: "Total number of OOM kill events",
	}, []string{"trigger_comm", "victim_comm"})

	// System metrics
	MemPressureGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "floatie_memory_pressure_score",
		Help: "Current memory pressure score (0-100)",
	})
)

// Register registers all metrics with the Prometheus client
func Register() {
	prometheus.MustRegister(
		ReadLatencyHist,
		WriteLatencyHist,
		OOMKillsCounter,
		MemPressureGauge,
	)
}