Name: openvpn-auth-okta
Version: 2.8.4
Release: 1%{?dist}
Summary: Go programming language
Group: Productivity/Networking/Security
License: MPL-2.0
URL: https://github.com/algolia/openvpn-auth-okta
Source0: %{name}-%{version}.tar.xz
Source1: vendor.tar.gz
Source99: %{name}.rpmlintrc

BuildRequires: golang-1.22
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
* Mon Jul 01 2024 Jeremy JACQUE <jeremy.jacque@algolia.com> - 2.8.4-1
- chore(deps): bump github.com/phuslu/log from 1.0.106 to 1.0.107
- chore(oktaApiAuth): use Chrome on Linux user agent along with Sec-CH headers
- chore(oktaApiAuth): improve Push factor debugging

* Wed Jun 26 2024 Jeremy JACQUE <jeremy.jacque@algolia.com> - 2.8.3-1
- chore(dist): build using Golang 1.22
- fix(Makefile): raspbian always needs CGO
- chore(deps): bump github.com/phuslu/log from 1.0.97 to 1.0.100
- chore(deps): bump github.com/phuslu/log from 1.0.100 to 1.0.101
- chore(deps): bump github.com/phuslu/log from 1.0.101 to 1.0.102
- chore(deps): bump github.com/go-playground/validator/v10
- chore(doc): fix codacy warnings in README
- chore(ci): disable codacy checks for fixtures and test code
- chore(doc): add codacy badge
- fix(Makefile): /etc/os-release does not exist on MacOS, test before sourcing
- chore(ci): push coverage report to Codacy
- chore(lib): deduplicate identical piece of code
- chore(doc): fix more markdown warnings
- chore(deps): bump github.com/phuslu/log from 1.0.102 to 1.0.106
- chore(deps): bump github.com/go-playground/validator/v10
- chore: use sentinel errors when possible
- fix(oktaApiAuth): do not print authRes.Result when it is empty
- refacto(oktaApiAuth): dedup JSON api response processing
- chore(doc): update coverage badge
- fix(oktaApiAuth): gofmt
- test(oktaApiAuth): use assert.EqualError instead of assert.Equal
- test: use testify dedicated errors functions
- fix: use a valid hardcoded user agent
- chore(doc): update available package distros and archs
- fix(oktaApiAuth): respect Go style guide
- fix(oktaApiAuth): use fmt.Errorf instead of errors.New of fmt string
- refacto(oktaApiAuth): simplify Okta Auth error handling using wrappers
- chore(doc): update coverage badge
- fix(oktaApiAuth): wrong authRes variable was tested
- test(oktaApiAuth): add tests for parseOktaError

* Tue May 07 2024 Jeremy Jacque <jeremy.jacque@algolia.com> - 2.8.2-1
- chore(deps): bump github.com/stretchr/testify from 1.8.4 to 1.9.0
- chore(deps): bump github.com/go-playground/validator/v10
- chore(deps): bump github.com/phuslu/log from 1.0.88 to 1.0.89
- chore(deps): bump github.com/phuslu/log from 1.0.89 to 1.0.90
- chore(deps): bump golang.org/x/net from 0.21.0 to 0.23.0
- chore(deps): bump github.com/phuslu/log from 1.0.90 to 1.0.91
- chore(deps): bump github.com/go-playground/validator/v10
- chore(deps): bump github.com/phuslu/log from 1.0.91 to 1.0.92
- chore(deps): bump github.com/phuslu/log from 1.0.92 to 1.0.93
- chore(deps): bump github.com/phuslu/log from 1.0.93 to 1.0.96
- chore(deps): bump github.com/phuslu/log from 1.0.96 to 1.0.97
- feat(lib): allow to use a struct for PluginEnv
- feat(lib): provide a way to compute lib args from plugin envp, args passed as a struct
- fix(Makefile): use proper inc dirs for gcc and cppcheck
- feat(lib): rename the C function computing args
- doc: add some comments
- fix(lib): gotfmt
- chore(lib): let the user allocate and free himself the ArgsOktaAuthValidatorV2 struct
- refacto(plugin): mutualize error code during lib related calls
- chore(cmd): add missing license header

* Mon Feb 26 2024 Jeremy Jacque <jeremy.jacque@algolia.com> 2.8.1-1
- chore(deps): bump github.com/google/uuid from 1.5.0 to 1.6.0
- chore(deps): bump github.com/go-playground/validator/v10
- chore(ci): check go fmt
- fix(cmd): gofmt

* Sun Feb 25 2024 Jeremy Jacque <jeremy.jacque@algolia.com> 2.8.0-1
- chore(deps): bump golang.org/x/crypto from 0.7.0 to 0.17.0
- chore(deps): bump golang.org/x/net from 0.8.0 to 0.17.0
- fix(oktaApiAuth): do not return "valid" http 500 on request error
- chore: add comments and basic traces
- chore(oktaApiAuth): add validity checks on Okta groups
- feat(validator): allow various log level and to set it up in the conf file
- chore(doc): update coverage badge
- chore: normalize validator constructor name
- chore: normalize oktaApiAuth constructor name
- chore(validator): if log level has been set in constructor, use it as default if not provided in config
- refacto: use phuslu/log instead of logrus for better perf/memory usage
- chore(go): clean sums

* Thu Feb 22 2024 Jeremy Jacque <jeremy.jacque@algolia.com> 2.7.0-1
- chore(go): add go-playground/validator for API response validation
- chore(go): use proper json unmarshaling/validation instead of string parsing for API responses
- refacto(oktaApiAuth): factorize common (first step) MFA verification code
- chore(oktaApiAuth/test): test MFA with multiple push retries
- refacto(oktaApiAuth/test): split TestAuth function
- chore(oktaApiAuth) respect API spec anf honor HTTP codes
- chore(oktaApiAuth/test): respect API spec anf honor HTTP codes
- chore(oktaApiAuth): factorize TOTP and Push MFA verification code
- refacto(oktaApiAuth): dedup and simplify doAuthFirstStep code
- fix(oktaApiAuth): Okta will never answer success at first push MFA verify call
- fix(oktaApiAuth): status is mandatory in a AuthResponse
- fix(oktaApiAuth): add missing cancel in verifyFactors, simplify if/else with return
- fix(oktaApiAuth): return proper error for checkAllowedGroups HTTP error
- chore(oktaApiAuth/test): cover all Auth scenarii
- chore(oktaApiAuth/test): increase coverage of CheckAllowedGroups
- chore(doc): update coverage badge
- chore(oktaApiAuth/test): add auth_invalid_totp_no_sum fixture file
- chore(oktaApiAuth): cancelAuth is a fire & forget, no need for return values
- chore(oktaApiAuth): add some debug messages
- chore(doc): update coverage badge
- fix(oktaApiAuth): reset AuthResponse at each loop iteration to prevent persistency issues
- chore: make TOTP to Push fallback configurable
- refacto: simplify code - remove else when not needed

* Fri Feb 09 2024 vagrant <jeremy.jacque@algolia.com> 2.6.1-1
- chore(go): fmt
- chore(ci): remove snyk jobs as we are decommissioning it
- chore(doc): simplify pkg install section by using OBS instruction page
- chore: add license header to source files

* Fri Dec 22 2023 Jeremy Jacque <jeremy.jacque@algolia.com> 2.6.0-1
- fix(plugin): add missing dlclose
- chore(Makefile): minimize built file size and trimpath
- chore(Makefile): clean unused vars and targets, tune go build params
- refacto(go): simplify logging by using different fomatter before and after username is set
- chore(doc): update coverage badge
- chore(doc): add a section about logs
- refacto(oktaApiAuth): split oktaApiAuth package into multiple files
- refacto(oktaApiAuth/test): split oktaApiAuth tests into multiple files
- refacto(validator): integrate utils pkg as it is only used by validator
- refacto(validator): split validator package into multiple files
- refacto(validator/test): split validator tests into multiple files
- refacto(Makefile): use a shell cmd to get the full list of pkg files for dependencies
- fix(Makefile): GOLDFLAGS has been renamed GOPLUGIN_LDFLAGS in a previous commit
- refacto(oktaApiAuth/test): use types_test.go only for stuff common to multiple tests
- refacto(validator): move checkControlFilePerm to utils(_test)
- chore(oktaApiAuth): add a todo for Pool only used in tests

* Tue Dec 19 2023 Jeremy Jacque <jeremy.jacque@algolia.com> 2.5.10-1
- chore(oktaApiAuth): rephrase/enrich log outputs
- chore(validator): rephrase/enrich log outputs
- chore: create a dedicated func for logging setup (formatting with uuid, log-level)
- chore(go): add uuid package needed for logging
- chore(tools): update url for https://toolkit.okta.com/apps/

* Mon Dec 18 2023 Jeremy Jacque <jeremy.jacque@algolia.com> 2.5.9-1
- refacto(oktaApiAuth): handle totp and push MFA sequentialy with different error msg
- chore(oktaApiAuth/test): rename MFA errors, add test for invalid response for totp auth
- fix(oktaApiAuth): continue outer loop when push triggers error and not last
- chore(oktaApiAuth/test): test if multiple TOTP or push providers are possible
- chore(doc): update coverage badge
- refacto(oktaApiAuth): split validateUserMFA with 2 more functions (TOTP and push)
- chore(oktaApiAuth/test): implement tests following refacto

* Sat Dec 16 2023 Jeremy Jacque <jeremy.jacque@algolia.com> 2.5.8-1
- fix(oktaApiAuth): user may have multiple OTP providers, try all

* Sat Dec 16 2023 Jeremy Jacque <jeremy.jacque@algolia.com> 2.5.7-1
- fix(oktaApiAuth): handle properly transaction cancelation, only when needed
- fix(oktaApiAuth/test): fix with new calls to transaction cancellation
- chore(doc): update coverage badge
- chore(oktaApiAuth): homogenize / clean auth logs
- fix(oktaApiAuth): handle properly TOTP error (invalid passcode)
- chore(oktaApiAuth): simplify validateMFA signature
- chore(oktaApiAuth): rename some functions/vars for better readability
- fix(oktaApiAuth): respect MFAPushMaxRetries count, saves an API call/MFAPushDelaySeconds sleep
- feat(oktaApiAuth): handle expired password (only when no active MFA)
- chore(config): clean a bit api.ini config template
- chore(doc): rearrange and fix typo in README
- fix(dist): add missing packages in dsc

* Fri Dec 15 2023 Jeremy Jacque <jeremy.jacque@algolia.com> 2.5.6-1
- style: gofmt some source files
- refacto(oktaApiAuth): reduce gocyclo score of Auth to an acceptable score
- chore(oktaApiAuth): homogenize some Auth logs
- chore(oktaApiAuth/test): add a test for invalid preauth response
- chore(doc): update coverage badge

* Thu Dec 14 2023 Jeremy Jacque <jeremy.jacque@algolia.com> 2.5.5-1
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

