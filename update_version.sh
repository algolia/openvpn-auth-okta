#!/bin/bash

# Update all dist, debian files when bumping version
#
# Needs https://github.com/agx/git-buildpackage

version=$1

branch=$(git rev-parse --abbrev-ref HEAD)

git tag -f -a "v${version}" -m "v${version}"

sed -i'' -e "s/^\(Version: \).*/\1${version}/" dist/openvpn-auth-okta.spec
gbp rpm-ch --packaging-branch="${branch}" \
  --packaging-tag="v%(version)s" \
  --spec-file=dist/openvpn-auth-okta.spec \
  --git-author \
  --spawn-editor=no

git add dist/openvpn-auth-okta.spec
git commit -m "chore(dist): Update changelog for ${version} release"

sed -i'' -e "s/^\(DEBTRANSFORM-TAR: openvpn-auth-okta-\).*\(\.tar\.xz\)$/\1${version}\2/" dist/openvpn-auth-okta.dsc
sed -i'' -e "s/^\(Version: \).*/\1${version}/" dist/openvpn-auth-okta.dsc
git add dist/openvpn-auth-okta.dsc

gbp dch --debian-branch="${branch}" \
  -c --commit-msg="chore(debian): Update changelog for %(version)s release" \
  --release \
  --git-author \
  --distribution=stable --force-distribution \
  --spawn-editor=no \
  --debian-tag="v%(version)s" \
  -N "${version}"

git tag -f -a "v${version}" -m "v${version}"
