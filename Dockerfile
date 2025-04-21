FROM ubuntu:22.04

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

# Copy Go application
WORKDIR /app
COPY . .

# Install Go dependencies and compile with optimizations
RUN go generate ./... && \
    CGO_ENABLED=0 go build -o floatie -ldflags="-s -w" -trimpath ./cmd/floatie

# Run with minimal privileges
ENTRYPOINT ["/app/floatie"]