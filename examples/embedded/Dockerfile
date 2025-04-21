# Stage 1: Build Floatie
FROM ubuntu:22.04 as floatie-builder

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    clang \
    llvm \
    libelf-dev \
    libbpf-dev \
    linux-headers-generic \
    pkg-config \
    curl \
    ca-certificates && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Install Go
ENV GO_VERSION=1.21.1
RUN curl -LO https://golang.org/dl/go${GO_VERSION}.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz && \
    rm go${GO_VERSION}.linux-amd64.tar.gz
ENV PATH="/usr/local/go/bin:${PATH}"

# Copy Floatie source
WORKDIR /build/floatie
COPY . .

# Build Floatie binary
RUN go generate ./pkg/ebpf && \
    CGO_ENABLED=0 go build -o floatie -ldflags="-s -w" -trimpath ./cmd/floatie

# Stage 2: Create application image with Floatie embedded
FROM python:3.11-slim

# Install dependencies for Floatie
RUN apt-get update && apt-get install -y --no-install-recommends \
    kmod \
    libelf1 \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Add Floatie binary
COPY --from=floatie-builder /build/floatie/floatie /usr/local/bin/floatie

# Install your application
WORKDIR /app
COPY examples/embedded/app.py .
RUN pip install --no-cache-dir flask prometheus_client

# Set permissions
RUN chmod +x /usr/local/bin/floatie

# Copy the startup script
COPY examples/embedded/start.sh /start.sh
RUN chmod +x /start.sh

# Run the start script that launches both the app and Floatie
ENTRYPOINT ["/start.sh"]