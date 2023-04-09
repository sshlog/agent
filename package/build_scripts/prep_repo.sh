#!/bin/bash
set -e

git config --global --add safe.directory '*'
git submodule update --init --recursive
rm -Rf drone_src || true; mkdir drone_src
cp -r * drone_src/ || true
cd drone_src/
ln -s distros/debian debian || true