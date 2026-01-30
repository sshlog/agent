# --- Stage 1: Builder ---
FROM debian:bookworm-slim AS builder

ENV DEBIAN_FRONTEND=noninteractive
ENV INSTALL_TARGET_DIR=/tmp/sshlog-install
SHELL ["/bin/bash", "-c"]

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    clang-19 \
    llvm \
    libelf-dev \
    libbpf-dev \
    pkg-config \
    linux-libc-dev \
    flex \
    bison \
    python3-docutils \
    python3-virtualenv \
    && ln -s /usr/bin/clang-19 /usr/bin/clang \
    && rm -rf /var/lib/apt/lists/*


WORKDIR /source

# Copy the library source code
COPY CMakeLists.txt .
COPY libsshlog/ ./libsshlog/
COPY cmake/ ./cmake/


# Create build directory and compile
WORKDIR /source/build


RUN cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo \
          -DCMAKE_INSTALL_PREFIX=/usr \
          -DCMAKE_INSTALL_SYSCONFDIR=/etc .. \
    && make -j$(nproc)

# Install to a temporary directory
RUN make install DESTDIR=${INSTALL_TARGET_DIR} 

# RUN mkdir -p ${INSTALL_TARGET_DIR}/usr/bin/ && \
#     cp libsshlog/sshlog_cli ${INSTALL_TARGET_DIR}/usr/bin/

WORKDIR /source

# Copy the daemon source code and prep the python build env
COPY daemon/ ./daemon/
RUN rm -Rf /tmp/sshlog_venv 2>/dev/null && \
    virtualenv /tmp/sshlog_venv && \
    source /tmp/sshlog_venv/bin/activate && \
    pip3 install -r daemon/requirements.txt


RUN daemon/build_binary.sh && \
    mkdir -p ${INSTALL_TARGET_DIR}/usr/bin/ && cp dist/* ${INSTALL_TARGET_DIR}/usr/bin/ && \
    mkdir -p ${INSTALL_TARGET_DIR}/var/log/sshlog && chmod 700 ${INSTALL_TARGET_DIR}/var/log/sshlog && \
    mkdir -p ${INSTALL_TARGET_DIR}/etc/sshlog/conf.d && \
    mkdir -p ${INSTALL_TARGET_DIR}/etc/sshlog/plugins && \
    mkdir -p ${INSTALL_TARGET_DIR}/etc/sshlog/samples && \
    cp daemon/config_samples/*.yaml ${INSTALL_TARGET_DIR}/etc/sshlog/samples/ && \
    # Copy the session and event log config to the conf.d folder
    cp ${INSTALL_TARGET_DIR}/etc/sshlog/samples/log_all_sessions.yaml ${INSTALL_TARGET_DIR}/etc/sshlog/conf.d && \
    cp ${INSTALL_TARGET_DIR}/etc/sshlog/samples/log_events.yaml ${INSTALL_TARGET_DIR}/etc/sshlog/conf.d 

# --- Stage 2: Production ---
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libelf1 \
    libbpf1 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy the compiled artifacts
COPY --from=builder /tmp/sshlog-install /

# Ensure directories exist
RUN mkdir -p /var/log/sshlog /etc/sshlog

# Daemon must run as root to access the Kernel BPF subsystem
USER root

CMD ["/usr/bin/sshlogd"]
