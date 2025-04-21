# Floatie Embedded Example

This example demonstrates how to embed Floatie directly inside your application container for monitoring OverlayFS latency and OOM kill events.

## How It Works

This example consists of:

1. A multi-stage Dockerfile that:
   - Builds Floatie from source
   - Embeds the Floatie binary in your application container
   - Starts both Floatie and your application using a common startup script

2. A simple Python Flask application that:
   - Creates and reads files to generate OverlayFS activity
   - Exposes its own Prometheus metrics on port 8000

3. A complete monitoring stack with:
   - Prometheus to collect metrics from both the app and Floatie
   - Grafana with pre-configured dashboards

## Running the Example

```bash
# Start the entire stack
docker-compose up -d

# Access the services
- Application: http://localhost:8080
- Application Metrics: http://localhost:8000
- Floatie Metrics: http://localhost:9090
- Prometheus: http://localhost:9091
- Grafana: http://localhost:3000 (admin/admin)
```

## Testing OverlayFS Latency

Visit http://localhost:8080/heavy to trigger a high-latency OverlayFS operation. You should see spikes in the OverlayFS latency metrics in the Grafana dashboard.

## Important Notes

- This example requires:
  - Linux kernel 5.8+ for BPF ring buffer support
  - Docker with privileged capabilities enabled
  - Host mounts for `/sys/kernel/debug`, `/sys/fs/bpf`, and `/sys/fs/cgroup`

- For production use, you may want to:
  - Further restrict capabilities beyond just `SYS_ADMIN`, `SYS_RESOURCE`, and `BPF`
  - Implement a more graceful shutdown procedure
  - Consider whether your app container needs elevated privileges or if you can run Floatie as a sidecar