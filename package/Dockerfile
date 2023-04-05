FROM ubuntu:20.04
MAINTAINER Matt Hill <matt@openkilt.com>

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
      binutils           \
      build-essential    \
      clang-12           \
      cmake              \
      debhelper          \
      devscripts         \
      dh-python          \
      dh-systemd         \
      git                \
      libelf-dev         \
      linux-tools-$(uname -r) \
      llvm               \
      pkg-config         \
      python3            \
      python3-dev        \
      python3-pip        \
      python3-virtualenv \
      rpm             && \
      rm -rf /var/lib/apt/lists/* && \
      ln -s /usr/bin/clang-12 /usr/bin/clang



