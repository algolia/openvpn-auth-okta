#!/bin/bash

# Update all dist, debian files when bumping version

version=$1

git tag -f -a "v${version}" -m "v${version}"

sed -i'' -e "s/^\(Version: \).*/\1${version}/" dist/okta-openvpn.spec
gbp rpm-ch --packaging-branch=v2 \
  --packaging-tag="v%(version)s" \
  --spec-file=dist/okta-openvpn.spec \
  --git-author \
  --spawn-editor=no

git add dist/okta-openvpn.spec
git commit -m "chore(dist): Update changelog for ${version} release"

sed -i'' -e "s/^\(DEBTRANSFORM-TAR: okta-openvpn-\).*\(\.tar\.xz\)$/\1${version}\2/" dist/okta-openvpn.dsc
gbp dch --debian-branch=v2 \
  -c --commit-msg="chore(debian): Update changelog for %(version)s release" \
  --release \
  --git-author \
  --spawn-editor=no \
  --debian-tag="v%(version)s" \
  -N "${version}"

sed -i'' -e "s/^\(Version: \).*/\1${version}/" dist/okta-openvpn.dsc

git tag -f -a "v${version}" -m "v${version}"
