#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

# Build daemon
export PATH=${PATH}:/usr/local/bin/

rm -Rf /tmp/sshbouncer_venv 2>/dev/null
virtualenv /tmp/sshbouncer_venv
source /tmp/sshbouncer_venv/bin/activate
pip3 install -r ${SCRIPT_DIR}/requirements.txt 


# For example, output will be --hidden-import slack_sdk --hidden-import requests
HIDDEN_IMPORTS=$(findimports --ignore-stdlib  ${SCRIPT_DIR}/plugins/actions/ ${SCRIPT_DIR}/plugins/filters/ | grep -v 'plugins\.' | grep -v "^\s*$" | sed 's/^\s*/--hidden-import /g' | xargs)

pyinstaller --onefile $HIDDEN_IMPORTS ${SCRIPT_DIR}/daemon.py -n sshbouncerd

# Build client

client_imports=$(findimports --ignore-stdlib  ${SCRIPT_DIR}/cli/ | grep -v 'cli\.' | grep -v "comms\." | grep -v "^\s*$" | sed 's/^\s*/--hidden-import /g' | xargs)

pyinstaller --onefile $CLIENT_IMPORTS ${SCRIPT_DIR}/client.py -n sshbouncer

echo "Python binaries built in dist/ folder"