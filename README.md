# Floatie

Floatie is an eBPF-powered observability tool for monitoring container performance. It uses eBPF probes to provide insights into overlayFS latency and OOM kill events, helping you stay afloat in the chaotic seas of containerized environments.

## Features

- **OverlayFS Monitoring**: Track read and write latencies in containerized overlayFS operations
- **OOM Kill Detection**: Capture detailed information about Out-of-Memory events including trigger and victim processes
- **Prometheus Integration**: Export metrics for integration with your existing monitoring stack
- **Container-Aware**: Filter events by PID namespace to focus on specific containers
- **Lightweight**: Minimal overhead using efficient eBPF programs

## Requirements

- Linux kernel 5.8+ (for BPF ring buffer support)
- `CAP_BPF`, `CAP_SYS_ADMIN`, and `CAP_SYS_RESOURCE` capabilities
- Mount access to `/sys/kernel/debug`, `/sys/fs/bpf`, and `/sys/fs/cgroup`

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/floatie.git
cd floatie

# Build the binary
go generate ./...
go build -o floatie ./cmd/floatie

# Or use Docker
docker build -t floatie:latest .
```

## Usage

```bash
# Run directly
sudo ./floatie --pid-ns-inum 0 --max-map-entries 1024

# Or run with Docker
docker run --rm -it \
    --cap-add=SYS_ADMIN,SYS_RESOURCE,BPF \
    --pid=host \
    -v /sys/kernel/debug:/sys/kernel/debug \
    -v /sys/fs/bpf:/sys/fs/bpf \
    -v /sys/fs/cgroup:/sys/fs/cgroup \
    -p 9090:9090 \
    floatie:latest --pid-ns-inum 0 --max-map-entries 1024
```

Access Prometheus metrics at `http://localhost:9090/metrics`

## License

[MIT License](LICENSE)