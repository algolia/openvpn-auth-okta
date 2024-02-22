Format: 3.0 (native)
DEBTRANSFORM-RELEASE: 1
Source: openvpn-auth-okta
Binary: openvpn-auth-okta
Architecture: any
Version: 2.7.0
DEBTRANSFORM-TAR: openvpn-auth-okta-2.7.0.tar.xz
Maintainer: Foundation Squad <foundation@algolia.com>
Homepage: https://github.com/algolia/openvpn-auth-okta
Standards-Version: 4.5.10
Build-Depends: debhelper, make, gcc, golang-1.21 | golang-1.22
Package-List:
 openvpn-auth-okta deb base optional arch=any
 okta-auth-validator deb base optional arch=any
 libokta-auth-validator deb base optional arch=any
 libokta-auth-validator-dev deb base optional arch=all
 okta-auth-validator-common deb base optional arch=all
