#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

# Build daemon
export PATH=${PATH}:/usr/local/bin/

rm -Rf /tmp/sshlog_venv 2>/dev/null
virtualenv /tmp/sshlog_venv
source /tmp/sshlog_venv/bin/activate
pip3 install -r ${SCRIPT_DIR}/requirements.txt 


# For example, output will be --hidden-import slack_sdk --hidden-import requests
HIDDEN_IMPORTS=$(findimports --ignore-stdlib  ${SCRIPT_DIR}/plugins/actions/ ${SCRIPT_DIR}/plugins/filters/ | grep -v 'plugins\.' | grep -v "^\s*$" | sed 's/^\s*/--hidden-import /g' | xargs)

# Grab all the plugins and add them to the package so that they can be loaded dynamically at runtime
# format is --add-data 'plugins/actions/logfile_action.py:plugins/actions'
ACTION_PLUGINS=$(find $SCRIPT_DIR/plugins/actions -name "*.py" | awk '{print "--add-data " $1 ":plugins/actions";}' | xargs)
FILTER_PLUGINS=$(find $SCRIPT_DIR/plugins/filters -name "*.py" | awk '{print "--add-data " $1 ":plugins/filters";}' | xargs)

pyinstaller --onefile $HIDDEN_IMPORTS $ACTION_PLUGINS $FILTER_PLUGINS ${SCRIPT_DIR}/daemon.py -n sshlogd

# Build client

client_imports=$(findimports --ignore-stdlib  ${SCRIPT_DIR}/cli/ | grep -v 'cli\.' | grep -v "comms\." | grep -v "^\s*$" | sed 's/^\s*/--hidden-import /g' | xargs)

pyinstaller --onefile $CLIENT_IMPORTS ${SCRIPT_DIR}/client.py -n sshlog

echo "Python binaries built in dist/ folder"