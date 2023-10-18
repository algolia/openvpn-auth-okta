Name: okta-openvpn
Version: 2.3.2
Release: 1%{?dist}
Summary: Go programming language
Group: Productivity/Networking/Security
License: MPL-2.0
URL: https://github.com/algolia/okta-openvpn
Source0: %{name}-%{version}.tar.xz
Source1: vendor.tar.gz
Source99: %{name}.rpmlintrc

BuildRequires: golang-1.21
BuildRequires: gcc
BuildRoot: %{_tmppath}/%{name}-%{version}-build

%define plugin_dir %{_libdir}/openvpn/plugins

%description
This is a plugin/binary for OpenVPN (Community Edition) that authenticates users directly against Okta, with support for MFA (TOTP or PUSH only).

%prep
%setup -q
tar xf ../../SOURCES/vendor.tar.gz

%build
make

%install
make DESTDIR=%{buildroot} LIB_PREFIX=%{_libdir} install

%files
%defattr(-,root,root)
%dir %{_libdir}/openvpn
%dir %{plugin_dir}/
%dir /etc/openvpn/
%attr(0755,root,root) /usr/bin/okta_openvpn
%attr(0644,root,root) %{plugin_dir}/defer_simple.so
%attr(0644,root,root) %{plugin_dir}/openvpn-plugin-okta.so
%attr(0644,root,root) %{_libdir}/libokta-openvpn.so
%attr(0644,root,root) %{_includedir}/libokta-openvpn.h
%attr(0644,root,root) %config(noreplace) /etc/openvpn/okta_pinset.cfg
%attr(0640,root,root) %config(noreplace) /etc/openvpn/okta_openvpn.ini


%changelog
* Wed Oct 18 2023 root <jeremy.jacque@algolia.com> 2.3.2-1
- chore(Makefile): add missing soname to shared lib
- chore(Makefile): binary should bo to /usr/bin
- chore(dist): add files needed to build packages
- chore(dist): add script to manage versions

