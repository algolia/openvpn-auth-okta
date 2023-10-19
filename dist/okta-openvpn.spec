%define source_name okta-openvpn

Name: openvpn-auth-okta
Version: 2.4.0
Release: 1%{?dist}
Summary: Go programming language
Group: Productivity/Networking/Security
License: MPL-2.0
URL: https://github.com/algolia/okta-openvpn
Source0: %{source_name}-%{version}.tar.xz
Source1: vendor.tar.gz
Source99: %{source_name}.rpmlintrc

BuildRequires: golang-1.21
BuildRequires: gcc
BuildRequires: make
Requires: libokta-auth-validator = %{version}

BuildRoot: %{_tmppath}/%{name}-%{version}-build

%define plugin_dir %{_libdir}/openvpn/plugins

%description
This is a plugin for OpenVPN (Community Edition) that authenticates users directly against Okta, with support for MFA.


%package -n okta-auth-validator
Summary: Command line tool to authenticate against Okta.

%description -n okta-auth-validator
This is a command line tool that authenticates users directly against Okta, with support for MFA.


%package -n libokta-auth-validator
Summary: Shared library to authenticate against Okta.

%description -n libokta-auth-validator
Shared library that allows to authenticates user directly against Okta, with support for MFA.


%package -n libokta-auth-validator-devel
Summary: Development files for libokta-auth-validator.
Requires: libokta-auth-validator = %{version}

%description -n libokta-auth-validator-devel
Development files for libokta-auth-validator, a shared library that allows to authenticates user directly against Okta, with support for MFA.


%prep
%setup -q -n %{source_name}-%{version}
tar xf ../../SOURCES/vendor.tar.gz

%build
make

%install
make DESTDIR=%{buildroot} LIB_PREFIX=%{_libdir} install

%files
%dir %{_libdir}/openvpn
%dir %{plugin_dir}/
%dir /etc/openvpn/
%attr(0644,root,root) %{plugin_dir}/openvpn-plugin-okta.so
%attr(0644,root,root) %config(noreplace) /etc/openvpn/okta_pinset.cfg
%attr(0640,root,root) %config(noreplace) /etc/openvpn/okta_openvpn.ini

%files -n okta-auth-validator
%attr(0755,root,root) /usr/bin/okta-auth-validator

%files -n libokta-auth-validator
%attr(0644,root,root) %{_libdir}/libokta-auth-validator.so

%files -n libokta-auth-validator-devel
%attr(0644,root,root) %{_includedir}/libokta-auth-validator.h


%changelog
* Thu Oct 19 2023 vagrant <jeremy.jacque@algolia.com> 2.4.0-1
- chore(debian): split package
- chore(dist): split package
- chore(dist): update rpmlintrc filters
- fix(tools): work on current branch to generate changelogs

* Wed Oct 18 2023 vagrant <jeremy.jacque@algolia.com> 2.3.4-1
- chore(tools): fix distro name in changelog creation
- fix(Makefile): wrong soname for golang c-shared lib
- chore: remove unneeded defer_simple source code
- chore(doc): add section about package installation
- chore(dist): remove refs to defer_simple in spec file
- chore(dist): bump version

* Wed Oct 18 2023 root <root@default-ubuntu-2004.vagrantup.com> 2.3.3-1
- chore(Makefile): refacto to handle properly dlopened libokta-openvpn.so
- chore(debian): adapt rules after Makefile refacto
- fix(defer_okta_openvpn): context is needed, dlopen is mandatory to respect signals
- fix(defer_simple): passing wrong args array to deferred_auth_handler
- chore(pkg): use a struct instead of env to hold shared lib setup
- chore(cmd/lib): use new validator.Setup params
- chore(doc): update coverage badge
- chore(debian): update version
- chore(Makefile): symlink is not needed as dlopen follows ld.so
- chore(Makefile): add missing soname to shared lib
- chore(Makefile): binary should bo to /usr/bin
- chore(dist): add files needed to build packages
- chore(dist): add script to manage versions
- chore(debian): Update changelog for 2.3.2 release
- chore(dist): Update changelog for 2.3.2 release
- chore(debian): add source format
- fix(Makefile): create bin dir before install
- fix(debian): wrong package format
- chore(defer_okta_openvpn): fix indent, do not store useless pointer in context
- chore: rename function for clarity
- chore(Makefile): DESTDIR should be empty by default
- chore: rename okta_openvpn to okta-auth-validator to be more generic
- fix(lib): wrong (previous) export function name
- chore: rename C source file
- chore: rename lib to be more generic
- chore(oktaApiAuth): do not flood openvpn logs with useless messages

* Wed Oct 18 2023 root <jeremy.jacque@algolia.com> 2.3.2-1
- chore(Makefile): add missing soname to shared lib
- chore(Makefile): binary should bo to /usr/bin
- chore(dist): add files needed to build packages
- chore(dist): add script to manage versions

