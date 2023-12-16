Format: 3.0 (native)
DEBTRANSFORM-RELEASE: 1
Source: openvpn-auth-okta
Binary: openvpn-auth-okta
Architecture: any
Version: 2.5.6
DEBTRANSFORM-TAR: openvpn-auth-okta-2.5.6.tar.xz
Maintainer: Foundation Squad <foundation@algolia.com>
Homepage: https://github.com/algolia/openvpn-auth-okta
Standards-Version: 4.5.10
Build-Depends: debhelper, make, gcc, golang-1.21
Package-List:
 openvpn-auth-okta deb base optional arch=any
 okta-auth-validator deb base optional arch=any
 libokta-auth-validator deb base optional arch=any
 libokta-auth-validator-dev deb base optional arch=all
 okta-auth-validator-common deb base optional arch=all
