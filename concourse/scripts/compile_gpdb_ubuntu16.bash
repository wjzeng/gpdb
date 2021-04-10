#!/usr/bin/env bash
set -eo pipefail

# start docker in docker
. docker-in-concourse/dind.bash
max_concurrent_downloads=4
max_concurrent_uploads=4
start_docker ${max_concurrent_downloads} ${max_concurrent_uploads} "" ""

set -x

# copy gpaddon dir
mkdir -p gpdb_src/gpAux/addon
cp -r gpaddon_src/* gpdb_src/gpAux/addon

# Build ubuntu_ent_build:16.04_dist and create greenplum tarball
make -C gpdb_src/src/tools/docker/ubuntu16
cp /tmp/bin_gpdb.tar.gz gpdb_artifacts/

# Build debian-build:5X_STABLE and create greenplum debian package
docker build --tag debian-build:5X_STABLE gpdb_src/src/tools/docker/ubuntu16-debian/debian
docker run -it --rm -v $PWD/gpdb_artifacts:/output debian-build:5X_STABLE bash -c "cp /tmp/greenplum-db*.deb /output"
