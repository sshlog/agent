#!/bin/bash

# exit when any command fails
set -e

# Script used by both deb and rpm packaging to prepare the install directory
# with deliverable files

TARGET_BASE_DIR=$1

if [ -z "$TARGET_BASE_DIR" ]
then
      echo "Usage: $0 [target_base_dir]"
      exit 1
fi

mkdir -p ${TARGET_BASE_DIR}/usr/bin/ && cp dist/* ${TARGET_BASE_DIR}/usr/bin/
mkdir -p ${TARGET_BASE_DIR}/var/log/sshlog && chmod 700 ${TARGET_BASE_DIR}/var/log/sshlog
mkdir -p ${TARGET_BASE_DIR}/etc/sshlog/conf.d
mkdir -p ${TARGET_BASE_DIR}/etc/sshlog/plugins
mkdir -p ${TARGET_BASE_DIR}/etc/sshlog/samples
cp daemon/config_samples/* ${TARGET_BASE_DIR}/etc/sshlog/samples/

# Copy the session and event log config to the conf.d folder
cp ${TARGET_BASE_DIR}/etc/sshlog/samples/log_all_sessions.yaml ${TARGET_BASE_DIR}/etc/sshlog/conf.d
cp ${TARGET_BASE_DIR}/etc/sshlog/samples/log_events.yaml ${TARGET_BASE_DIR}/etc/sshlog/conf.d