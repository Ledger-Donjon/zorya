# SPDX-FileCopyrightText: 2025 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
#
# SPDX-License-Identifier: Apache-2.0

# Zorya - Concolic Execution Framework
# Multi-stage Dockerfile for building and running Zorya

# Stage 1: Build stage
FROM ubuntu:24.04 AS builder

# Avoid interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Set working directory
WORKDIR /zorya

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    clang \
    libclang-dev \
    libz3-dev \
    binutils-dev \
    git \
    curl \
    wget \
    unzip \
    flex \
    bison \
    python3 \
    python3-pip \
    openjdk-21-jdk \
    golang \
    && rm -rf /var/lib/apt/lists/*

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Install Ghidra
ARG GHIDRA_VERSION=12.0
ARG GHIDRA_RELEASE_DATE=20251205
ENV GHIDRA_INSTALL_DIR="/opt/ghidra"
RUN wget -q https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_RELEASE_DATE}.zip -O /tmp/ghidra.zip && \
    unzip -q /tmp/ghidra.zip -d /opt && \
    mv /opt/ghidra_${GHIDRA_VERSION}_PUBLIC ${GHIDRA_INSTALL_DIR} && \
    rm /tmp/ghidra.zip

# Install Pyhidra
RUN python3 -m pip install --upgrade --break-system-packages pyhidra

# Copy the entire project
COPY . /zorya

# Build pcode-generator and Zorya
RUN make -C external/pcode-generator all && \
    RUSTFLAGS="--cap-lints=allow" cargo build --release

# Stage 2: Runtime stage
FROM ubuntu:24.04

# Avoid interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libgomp1 \
    libz3-dev \
    python3 \
    python3-pip \
    openjdk-21-jdk \
    gdb \
    binutils \
    binutils-dev \
    netcat-openbsd \
    curl \
    build-essential \
    clang \
    libclang-dev \
    flex \
    bison \
    && rm -rf /var/lib/apt/lists/*

# Set JAVA_HOME for Ghidra
ENV JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64

# Install Rust (needed by wrapper script for pcode-generator)
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Copy Ghidra from builder
ENV GHIDRA_INSTALL_DIR="/opt/ghidra"
COPY --from=builder /opt/ghidra ${GHIDRA_INSTALL_DIR}

# Install Pyhidra in runtime
RUN python3 -m pip install --upgrade --break-system-packages pyhidra

# Copy built binaries and necessary files from builder
COPY --from=builder /zorya/target/release/zorya /opt/zorya/zorya
COPY --from=builder /zorya/external/pcode-generator /opt/zorya/external/pcode-generator
COPY --from=builder /zorya/external/pcode-parser /opt/zorya/external/pcode-parser
COPY --from=builder /zorya/src /opt/zorya/src
COPY --from=builder /zorya/scripts /opt/zorya/scripts
COPY --from=builder /zorya/Cargo.toml /opt/zorya/Cargo.toml
COPY --from=builder /zorya/Cargo.lock /opt/zorya/Cargo.lock
COPY --from=builder /zorya/README.md /opt/zorya/README.md
COPY --from=builder /zorya/LICENSE /opt/zorya/LICENSE
COPY --from=builder /zorya/tests /opt/zorya/tests

# Create results directory and configure wrapper script
RUN mkdir -p /opt/zorya/results/initialization_data && \
    sed -i 's|^_ZORYA_EMBED="__ZORYA_DIR__"|_ZORYA_EMBED="/opt/zorya"|' /opt/zorya/scripts/zorya && \
    chmod +x /opt/zorya/scripts/zorya

# Set environment variables
ENV ZORYA_DIR=/opt/zorya
ENV GHIDRA_INSTALL_DIR=/opt/ghidra
ENV PATH="/opt/zorya/scripts:/opt/ghidra/support:${PATH}"

# Ensure environment variables are available in all shells (for subprocesses)
RUN echo 'export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64' >> /etc/profile.d/zorya.sh && \
    echo 'export GHIDRA_INSTALL_DIR=/opt/ghidra' >> /etc/profile.d/zorya.sh && \
    echo 'export ZORYA_DIR=/opt/zorya' >> /etc/profile.d/zorya.sh && \
    echo 'export PATH="/opt/zorya/scripts:/opt/ghidra/support:$PATH"' >> /etc/profile.d/zorya.sh

# Set working directory to Zorya installation
WORKDIR /opt/zorya

# Default command
CMD ["/bin/bash"]
