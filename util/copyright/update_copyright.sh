#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )


find ${SCRIPT_DIR}/../../daemon -type f \( -name "*.py" \) | grep -vE '(venv|build)' | xargs addlicense -v -f ${SCRIPT_DIR}/copyright_template

find ${SCRIPT_DIR}/../../libsshlog -type f \( -name "*.cpp" -o -name "*.h" -o -name "*.c" \) | grep -vE '(libbpf|bpftool|build|vmlinux|libsshlog/bpf|concurrentqueue|lightweightsemaphore)' | xargs addlicense -v -f ${SCRIPT_DIR}/copyright_template

find ${SCRIPT_DIR}/../../libsshlog/bpf -type f \( -name "*.cpp" -o -name "*.h" -o -name "*.c" \) | grep -vE '(libbpf|bpftool|build|vmlinux)' | xargs addlicense -v -f ${SCRIPT_DIR}/bpf_copyright_template
