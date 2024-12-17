# -------------------------------------------------------
# Builder stage
# -------------------------------------------------------
FROM nvidia/cuda:12.4.0-devel-ubuntu22.04 AS builder
# Update and install dependencies without bpftool for now
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang llvm libelf-dev libbpf-dev pkg-config git build-essential curl \
    libssl-dev ca-certificates linux-tools-generic linux-tools-common && \
    rm -rf /var/lib/apt/lists/*

# Symlink bpftool to /usr/bin
RUN ln -s /usr/lib/linux-tools/*/bpftool /usr/bin/bpftool

# Install Rust toolchain
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH=/root/.cargo/bin:$PATH

# Set workdir
WORKDIR /app

# Copy the entire project into the container
COPY . .

# Since we already generated vmlinux.h on the host, it should be present in src/bpf/

# Build the Rust project in release mode
RUN cargo build --release

# -------------------------------------------------------
# Runtime stage
# -------------------------------------------------------
FROM nvidia/cuda:12.4.0-runtime-ubuntu22.04

# Install only minimal runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends libelf1 && \
    rm -rf /var/lib/apt/lists/*

# Symlink libcudart.so.12 to libcudart.so
RUN ln -s /usr/local/cuda/lib64/libcudart.so.12 /usr/local/cuda/lib64/libcudart.so


WORKDIR /app
COPY --from=builder /app/target/release/gpu_probe /usr/local/bin/gpu_probe
COPY --from=builder /app/readme-assets /app/readme-assets
# copy the memleaktest binary to test inside of docker
# COPY memleaktest /app/memleaktest

# Expose the Prometheus metrics port
EXPOSE 9000

# Run the GPU probe binary with some default arguments
CMD ["/usr/local/bin/gpu_probe", "--memleak", "--metrics-addr", "0.0.0.0:9000"]
    