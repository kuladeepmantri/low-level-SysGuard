# Auris - ARM Linux Syscall Tracer & Security Analyzer
# Multi-stage build for ARM64 Linux container

ARG TARGETPLATFORM=linux/arm64
FROM debian:bookworm-slim AS builder

# Install build dependencies
# Note: check library not available in bookworm, building without tests in container
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    pkg-config \
    libcurl4-openssl-dev \
    libssl-dev \
    libjson-c-dev \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /build

# Copy source files
COPY . .

# Build the application (without tests since libcheck not available)
RUN mkdir -p build && cd build && \
    cmake -DCMAKE_BUILD_TYPE=Release \
          -DBUILD_STATIC=OFF \
          -DBUILD_TESTS=OFF \
          .. && \
    make -j$(nproc)

# Runtime stage - minimal image
FROM debian:bookworm-slim AS runtime

# Install minimal runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libcurl4 \
    libjson-c5 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /data /config

# Copy the built binary
COPY --from=builder /build/build/auris /usr/local/bin/auris

# Set up non-root user for safer operation (can be overridden)
RUN useradd -m -s /bin/bash auris

# Default working directory for traces and profiles
WORKDIR /data

# Default entrypoint
ENTRYPOINT ["/usr/local/bin/auris"]
CMD ["--help"]

# Development stage with all tools
FROM builder AS development

# Install additional development tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    gdb \
    valgrind \
    strace \
    vim \
    less \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
CMD ["/bin/bash"]
