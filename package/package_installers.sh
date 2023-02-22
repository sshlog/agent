#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

docker build -t openkilt/builder:ubuntu2004 ${SCRIPT_DIR}

VOL_SHARE_DIR=/tmp/sshbouncer-pack
TAR_FILE_NAME=sshbouncer

rm -Rf $VOL_SHARE_DIR
mkdir -p $VOL_SHARE_DIR

# Copy the signing key
cp ${SCRIPT_DIR}/signing_keys/private.pgp ${VOL_SHARE_DIR}

git-archive-all --force-submodules --prefix=sshbouncer/ ${VOL_SHARE_DIR}/sshbouncer.tar.gz
cd $VOL_SHARE_DIR
tar xvfz sshbouncer.tar.gz
ln -s ${VOL_SHARE_DIR}/sshbouncer/distros/debian/ ${VOL_SHARE_DIR}/sshbouncer/debian


HOST_USER_ID=$(id -u)
HOST_GROUP_ID=$(id -g)

# This script executes inside the docker container in order to build the deb files and place them in the volume mount
echo """#!/bin/bash

gpg --import ${VOL_SHARE_DIR}/private.pgp

cd ${VOL_SHARE_DIR}/sshbouncer/
debuild -b
chown ${HOST_USER_ID}:${HOST_GROUP_ID} ${VOL_SHARE_DIR}/* -R
""" > ${VOL_SHARE_DIR}/sshbouncer/pack.sh
chmod +x ${VOL_SHARE_DIR}/sshbouncer/pack.sh


docker run --rm -v ${VOL_SHARE_DIR}:${VOL_SHARE_DIR} -it openkilt/builder:ubuntu2004 ${VOL_SHARE_DIR}/sshbouncer/pack.sh

rmdir -Rf ${SCRIPT_DIR}/dist 2>/dev/null
mkdir -p ${SCRIPT_DIR}/dist 2>/dev/null

cp ${VOL_SHARE_DIR}/*.deb ${SCRIPT_DIR}/dist/
echo "Deb packages available in ${SCRIPT_DIR}/dist/"