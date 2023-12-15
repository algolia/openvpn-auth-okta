Name: openvpn-auth-okta
Version: 2.5.6
Release: 1%{?dist}
Summary: Go programming language
Group: Productivity/Networking/Security
License: MPL-2.0
URL: https://github.com/algolia/openvpn-auth-okta
Source0: %{name}-%{version}.tar.xz
Source1: vendor.tar.gz
Source99: %{name}.rpmlintrc

BuildRequires: golang-1.21
BuildRequires: gcc
BuildRequires: make
Requires: libokta-auth-validator = %{version}
Requires: okta-auth-validator-common = %{version}

BuildRoot: %{_tmppath}/%{name}-%{version}-build

%define plugin_dir %{_libdir}/openvpn/plugins

%description
This is a plugin for OpenVPN (Community Edition) that authenticates users directly against Okta, with support for MFA.


%package -n okta-auth-validator
Summary: Command line tool to authenticate against Okta
Requires: okta-auth-validator-common = %{version}

%description -n okta-auth-validator
This is a command line tool that authenticates users directly against Okta, with support for MFA.

%package -n libokta-auth-validator
Summary: Shared library to authenticate against Okta
Requires: okta-auth-validator-common = %{version}

%description -n libokta-auth-validator
Shared library that allows to authenticates user directly against Okta, with support for MFA.


%package -n libokta-auth-validator-devel
Summary: Development files for libokta-auth-validator
Group: Development/Tools/Other
Requires: libokta-auth-validator = %{version}

%description -n libokta-auth-validator-devel
Development files for libokta-auth-validator, a shared library that allows to authenticates user directly against Okta, with support for MFA.

%package -n okta-auth-validator-common
Summary: Config files for libokta-auth-validator

%description -n okta-auth-validator-common
Config files for openvpn-auth-okta, okta-auth-validator, libokta-auth-validator


%prep
%setup -q -n %{name}-%{version}
tar xf ../../SOURCES/vendor.tar.gz

%build
make

%install
make DESTDIR=%{buildroot} LIB_PREFIX=%{_libdir} install

%files
%dir %{_libdir}/openvpn
%dir %{plugin_dir}/
%attr(0644,root,root) %{plugin_dir}/openvpn-plugin-auth-okta.so

%files -n okta-auth-validator-common
%dir /etc/okta-auth-validator/
%attr(0644,root,root) %config(noreplace) /etc/okta-auth-validator/pinset.cfg
%attr(0640,root,root) %config(noreplace) /etc/okta-auth-validator/api.ini

%files -n okta-auth-validator
%attr(0755,root,root) /usr/bin/okta-auth-validator

%files -n libokta-auth-validator
%attr(0644,root,root) %{_libdir}/libokta-auth-validator.so

%files -n libokta-auth-validator-devel
%attr(0644,root,root) %{_includedir}/libokta-auth-validator.h


%changelog
* Fri Dec 15 2023 vagrant <jeremy.jacque@algolia.com> 2.5.6-1
- style: gofmt some source files
- refacto(oktaApiAuth): reduce gocyclo score of Auth to an acceptable score
- chore(oktaApiAuth): homogenize some Auth logs
- chore(oktaApiAuth/test): add a test for invalid preauth response
- chore(doc): update coverage badge

* Thu Dec 14 2023 vagrant <jeremy.jacque@algolia.com> 2.5.5-1
- chore(validator): add msg for setup failures
- chore: use logrus to have a clean output
- fix(Makefile): missing source deps in targets
- chore(doc): update coverage badge
- fix(Makefile): allow to build on MacOS
- chore(validator): handle properly new config files names
- chore(Makefile): add proper MacOS ldflags for libs
- chore(oktaApiAuth): allow POST and GET in oktaReq
- feat(oktaApiAuth): check if user is a member of an AllowedGroup
- feat((oktaApiAuth/test): test checkAllowedGroups functions
- feat(config): add AllowedGroups option
- chore(doc): update coverage badge
- feat(oktaApiAuth/test): add invalid payload test
- chore(validator/test): check config file detection
- chore(validator/test): test wrongly formatted ini file
- chore(doc): update coverage badge
- chore(github): remove refs to pip in dependabot

* Thu Oct 26 2023 Jeremy Jacque <jeremy.jacque@algolia.com> 2.5.4-1
- chore: rename config files
- fix(doc): fix invalid license header
- chore(doc): small README updates
- chore(doc): remove CODE.md as the pkg is now referenced in pkg.go.dev
- chore(doc): update authors
- chore(dist): move tool to update packages version
- chore(config): move config files to a dedicated dir
- chore(Makefile): enforce some compiler options
- fix(debian): ensure proper config files permissions

* Wed Oct 25 2023 Jeremy Jacque <jeremy.jacque@algolia.com> 2.5.3-1
- style(utils): use gofmt std indentation
- style(oktaApiAuth): use gofmt std indentation
- style(validator): use gofmt std indentation
- style(cmd): use gofmt std indentation
- style(lib): use gofmt std indentation
- chore(doc): update coverage badge
- chore(doc): add doc ref and goreportcard badges
- chore(pkg): rename config files
- chore(Makefile): rename config files
- chore(dist): rename config files
- chore(doc): rename config files
- chore(git): rename config files

* Tue Oct 24 2023 Jeremy Jacque <jeremy.jacque@algolia.com> 2.5.2-1
- chore(oktaApiAuth): add comments for functions
- chore(utils): add comments for functions
- chore(validator): remove useless function
- chore(validator): add comments for functions
- chore(validator): do not set clientIp when not needed
- chore(oktaApiAuth): clientIp is not set anymore to 0.0.0.0
- chore(oktaApiAuth): add struct comments
- chore(validator): add struct comments

* Tue Oct 24 2023 Jeremy Jacque <jeremy.jacque@algolia.com> 2.5.1-1
- chore(pkg): relocate http pool initialisation from utils to oktaApiAuth
- chore(utils): simplify test
- chore(utils): add a function to remove comments from a slice
- chore(validator): remove from the pinset list empty lines and comments
- chore(utils): simplify CheckUsernameFormat

* Sun Oct 22 2023 Jeremy Jacque <jeremy.jacque@algolia.com> 2.5.0-1
- chore(pkg): remove now useless types package
- chore(oktaApiAuth): move types in pkg, split constructor, make needed struct fields public
- chore(oktaApiAuth/test): struct has been renamed, test InitPool
- chore(validator): move types in pkg, parse for passcode here, move okta api related struct
- chore(validator/test): adapt to latest changes, add more tests
- chore(lib): adapt to struct moves
- chore(testing): add new fixture for validator
- chore(doc): reflect latest changes
- chore(validator): remove useles comments, error test
- chore(doc): update coverage badge after new tests implem
- chore(debian): add missing common package for config files
- chore(dist): split RPM pkg to have a dedicated config file one
- chore(tools): small fix
- fix(dist): add missing description for okta-auth-validator-common
- chore(dist): fix some rpmlint issues
- chore(cfg): remove algolia ref

* Fri Oct 20 2023 Jeremy Jacque <jeremy.jacque@algolia.com> 2.4.3-1
- chore: change plugin file name to be aligned with other OpenVPN plugins
- chore(doc): fix typo in install section and add info about OpenVPN tmp dir
- chore(plugin): rename source according to new plugin file name
- chore(doc): update with new plugin name
- chore(git): now all produced files are in a dedicated dir, so ignore this dir

* Fri Oct 20 2023 Jeremy Jacque <jeremy.jacque@algolia.com> 2.4.2-1
- chore(validator): refacto to remove useless functions and better err control on Authenticate
- chore(cmd/okta-auth-validator): adapt to new Authenticate return type
- chore(lib): adapt to new Authenticate return type
- chore(validator/test): test new Authenticate err returned
- chore(oktaApiAuth/test): test the case where we need to sort the offered MFAs
- fix(validator/test): handle possible nil error
- chore(oktaApiAuth/test): test the case where preAuth fails (connection issue)
- chore(fixtures): add preauth_mfa_required_multi used by oktaApiAuth/TestAuth
- chore(doc): update coverage badge after new tests implem

* Thu Oct 19 2023 Jeremy Jacque <jeremy.jacque@algolia.com> 2.4.1-1
- chore: renamed repo and packages
- chore(github): add code owners and PR template
- chore(Makefile): change config files location
- chore(doc): change config files location
- chore(dist): change config files location
- chore(validator): change default config files location

* Thu Oct 19 2023 Jeremy Jacque <jeremy.jacque@algolia.com> 2.4.0-1
- chore(debian): split package
- chore(dist): split package
- chore(dist): update rpmlintrc filters
- fix(tools): work on current branch to generate changelogs

* Wed Oct 18 2023 Jeremy Jacque <jeremy.jacque@algolia.com> 2.3.4-1
- chore(tools): fix distro name in changelog creation
- fix(Makefile): wrong soname for golang c-shared lib
- chore: remove unneeded defer_simple source code
- chore(doc): add section about package installation
- chore(dist): remove refs to defer_simple in spec file
- chore(dist): bump version

* Wed Oct 18 2023 Jeremy Jacque <jeremy.jacque@algolia.com> 2.3.3-1
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

* Wed Oct 18 2023 Jeremy Jacque <jeremy.jacque@algolia.com> 2.3.2-1
- chore(Makefile): add missing soname to shared lib
- chore(Makefile): binary should bo to /usr/bin
- chore(dist): add files needed to build packages
- chore(dist): add script to manage versions

