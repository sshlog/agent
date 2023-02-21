#!/bin/bash

docker build -t openkilt/builder:ubuntu2004 .

VOL_SHARE_DIR=/tmp/sshbouncer-pack
TAR_FILE_NAME=sshbouncer

rm -Rf $VOL_SHARE_DIR
mkdir -p $VOL_SHARE_DIR

git-archive-all --force-submodules --prefix=sshbouncer/ ${VOL_SHARE_DIR}/sshbouncer.tar.gz
cd $VOL_SHARE_DIR
tar xvfz sshbouncer.tar.gz

echo """#!/bin/bash

cd ${VOL_SHARE_DIR}
debuild -b
""" > ${VOL_SHARE_DIR}/sshbouncer/pack.sh
chmod +x ${VOL_SHARE_DIR}/sshbouncer/pack.sh


docker run --rm -v ${VOL_SHARE_DIR}:${VOL_SHARE_DIR} -it openkilt/builder:ubuntu2004 ${VOL_SHARE_DIR}/sshbouncer/pack.sh