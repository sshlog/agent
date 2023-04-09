#!/bin/bash
set -e


curl -L https://github.com/openkilt/openrepo/releases/download/v1.0.0/openrepo_cli_$(uname -m) -o /usr/local/bin/openrepo
chmod +x /usr/local/bin/openrepo
openrepo upload -o --repo sshlog-ubuntu-latest ./*.deb
openrepo upload -o --repo sshlog-redhat-latest ./*.rpm