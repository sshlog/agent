#!/bin/bash
set -e

cd drone_src/
package/setup_drone_signingkey.sh
mkdir -p /usr/lib/rpm/macros.d/ && cp distros/redhat/macros/* /usr/lib/rpm/macros.d/
rpmbuild --build-in-place --define '_rpmdir ../' --define '_build_name_fmt %%{NAME}-%%{VERSION}-%%{RELEASE}.%%{ARCH}.rpm'  -bb distros/redhat/sshlog.spec
echo '%_gpg_name matt@openkilt.com' > ~/.rpmmacros
rpmsign --addsign ../*.rpm