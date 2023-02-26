#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

docker build -t openkilt/builder:ubuntu2004 ${SCRIPT_DIR}

VOL_SHARE_DIR=/tmp/sshlog-pack
TAR_FILE_NAME=sshlog

rm -Rf $VOL_SHARE_DIR
mkdir -p $VOL_SHARE_DIR

# Copy the signing key
cp ${SCRIPT_DIR}/signing_keys/private.pgp ${VOL_SHARE_DIR}

git-archive-all --force-submodules --prefix=sshlog/ ${VOL_SHARE_DIR}/sshlog.tar.gz
cd $VOL_SHARE_DIR
tar xvfz sshlog.tar.gz
ln -s ${VOL_SHARE_DIR}/sshlog/distros/debian/ ${VOL_SHARE_DIR}/sshlog/debian


HOST_USER_ID=$(id -u)
HOST_GROUP_ID=$(id -g)

# This script executes inside the docker container in order to build the deb files and place them in the volume mount
echo """#!/bin/bash

gpg --import ${VOL_SHARE_DIR}/private.pgp

cd ${VOL_SHARE_DIR}/sshlog/

# Build the debian package
debuild -b

# Build the redhat packages
mkdir -p /usr/lib/rpm/macros.d/ && cp distros/redhat/macros/* /usr/lib/rpm/macros.d/
rpmbuild --build-in-place --define '_rpmdir /tmp/sshlog-pack/' --define '_build_name_fmt %%{NAME}-%%{VERSION}-%%{RELEASE}.%%{ARCH}.rpm'  -bb distros/redhat/sshlog.spec
echo '%_gpg_name matt@openkilt.com' > ~/.rpmmacros
rpmsign --addsign ../*.rpm
chown ${HOST_USER_ID}:${HOST_GROUP_ID} ${VOL_SHARE_DIR}/* -R
""" > ${VOL_SHARE_DIR}/sshlog/pack.sh
chmod +x ${VOL_SHARE_DIR}/sshlog/pack.sh


docker run --rm -v ${VOL_SHARE_DIR}:${VOL_SHARE_DIR} -it openkilt/builder:ubuntu2004 ${VOL_SHARE_DIR}/sshlog/pack.sh

rmdir -Rf ${SCRIPT_DIR}/dist 2>/dev/null
mkdir -p ${SCRIPT_DIR}/dist 2>/dev/null

cp ${VOL_SHARE_DIR}/*.deb ${SCRIPT_DIR}/dist/
cp ${VOL_SHARE_DIR}/*.rpm ${SCRIPT_DIR}/dist/
echo "Deb/rpm packages available in ${SCRIPT_DIR}/dist/"
