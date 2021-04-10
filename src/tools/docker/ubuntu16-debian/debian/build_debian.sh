#!/usr/bin/env sh

set -ex

VERSION=$(</tmp/gpdb_src/VERSION awk '{print $1}')
dch --create -M --package greenplum-db -v "${VERSION}" "Enterprise Release"
yes | mk-build-deps -i debian/control
DEB_BUILD_OPTIONS='nocheck parallel=6' debuild -us -uc -b
echo The debian package is at /tmp/greenplum-db_${VERSION}.build.dev_amd64.deb
