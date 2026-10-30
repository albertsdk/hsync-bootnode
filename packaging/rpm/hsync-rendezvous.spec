%global _hsync_pkgdir %{pkgdir}

Name:           hsync-rendezvous
Version:        __VERSION__
Release:        1%{?dist}
Summary:        HSYNC - P2P rendezvous node (no-log)

License:        BSD-3-Clause
URL:            https://github.com/albertsdk/hsync-rendezvous
Packager:       Alberto Basso <17047798+albertsdk@users.noreply.github.com>

# PyInstaller onedir bundle carries its own Python runtime and private shared
# libraries; rpm's automatic dependency scanner would mis-detect them. Declare
# the real runtime requirements explicitly.
AutoReqProv:    no
Requires:       glibc
Requires:       systemd

%description
hsync-rendezvous is the Internet rendezvous node of the HSYNC sync network. It
tells P2P clients which peers are currently online, speaking the rdv/1
protocol over QUIC/UDP 443 (TLS 1.3, RETRY + address validation).

Everything lives in RAM with a 60-second TTL: no persistence, no logs, no PII
on disk.

%prep
exit 0

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}
cp -a %{_hsync_pkgdir}/. %{buildroot}/
# The group-keys directory is never shipped (the operator provisions it), but
# the package owns it so it is removed cleanly.
mkdir -p %{buildroot}/etc/hsync-rendezvous

%post
mkdir -p %{_sysconfdir}/hsync-rendezvous
chown root:root %{_sysconfdir}/hsync-rendezvous 2>/dev/null || true
chmod 0750 %{_sysconfdir}/hsync-rendezvous
# The unit reads /etc/hsync-rendezvous/group-keys as a systemd credential and
# LoadCredential= fails when the source is missing, so create it empty (open
# mode) unless the administrator already provisioned it.
if [ ! -e %{_sysconfdir}/hsync-rendezvous/group-keys ]; then
    : > %{_sysconfdir}/hsync-rendezvous/group-keys
    chown root:root %{_sysconfdir}/hsync-rendezvous/group-keys 2>/dev/null || true
    chmod 0600 %{_sysconfdir}/hsync-rendezvous/group-keys
fi
command -v restorecon >/dev/null 2>&1 && \
    restorecon -R %{_sysconfdir}/hsync-rendezvous /usr/lib/systemd/system/hsync-rendezvous.service 2>/dev/null || true
# Register the unit but do NOT enable or start it: opt-in
# ``systemctl enable --now hsync-rendezvous.service``.
systemctl daemon-reload 2>/dev/null || true
exit 0

%preun
if [ "$1" -eq 0 ]; then
    systemctl stop hsync-rendezvous.service 2>/dev/null || true
    systemctl disable hsync-rendezvous.service 2>/dev/null || true
fi
exit 0

%postun
systemctl daemon-reload 2>/dev/null || true
exit 0

%files
%dir %attr(0750,root,root) %{_sysconfdir}/hsync-rendezvous
%{_prefix}/lib/hsync-rendezvous
/usr/bin/hsync-rendezvous
%{_mandir}/man1/hsync-rendezvous.1.gz
/usr/lib/systemd/system/hsync-rendezvous.service

%changelog
