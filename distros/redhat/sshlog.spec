%define version_from_deb %(dpkg-parsechangelog --show-field version | sed -E 's/\.[0-9]+$//g')
%define patch_ver_from_deb %(dpkg-parsechangelog --show-field version | grep -Eo '\.[0-9]+$' | cut -c 2-)

Name: sshlog
Version: %{version_from_deb}
Release: %{patch_ver_from_deb}%{?dist}
Summary: SSH logging utility

License: RSALv2
URL: https://github.com/sshlog/sshlog
Source0: %{name}-%{version}.tar.gz

%{?systemd_requires}
#Buildrequires: systemd-rpm-macros
#BuildRequires: cmake
Requires: systemd

%description
sshlog is a tool that logs SSH activity.

# Ignore installed files that we don't use (e.g., symlink for libsshlog.so)
%define _unpackaged_files_terminate_build 0

%prep
%setup -q

%build
# If compiling for kernel version 5.8+, use -DUSE_RINGBUF=ON for more efficient data transfer
cmake \
    -DCMAKE_INSTALL_PREFIX=/usr \
    -DCMAKE_INSTALL_SYSCONFDIR=/etc \
    -DCMAKE_VERBOSE_MAKEFILE=OFF \
    -DCMAKE_COLOR_MAKEFILE=ON \
    -Bbuild_redhat/ -S.
cd build_redhat; make -j8;

%install
rm -rf %{buildroot}
cd build_redhat/
make install DESTDIR=%{buildroot}
cd ../

bash -x ./daemon/build_binary.sh
bash -x ./distros/prep_install.sh %{buildroot}
# Setup systemd config
mkdir -p %{buildroot}/usr/lib/systemd/system-preset/
echo "enable sshlog.service" > %{buildroot}/usr/lib/systemd/system-preset/80-sshlog.preset
mkdir -p %{buildroot}/usr/lib/systemd/system/
cp distros/redhat/sshlog.service %{buildroot}/usr/lib/systemd/system/ 

%clean
rm -rf %{buildroot}

# Add a group for sshlog
%pre
groupadd sshlog 2>/dev/null || true

# Install the systemd service
%post
%systemd_post sshlog.service

%postun
%systemd_postun_with_restart sshlog.service

%posttrans
# Start sshlog on install
systemctl daemon-reload
systemctl restart sshlog

%files
%defattr(-,root,root,-)
/usr/bin/*
/usr/lib/libsshlog.so.1
/var/log/sshlog
/etc/sshlog/*
/usr/lib/systemd/system/sshlog.service
/usr/lib/systemd/system-preset/*.preset
