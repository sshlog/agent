#!/bin/bash
set -e

cd drone_src/
package/setup_drone_signingkey.sh
debuild -b