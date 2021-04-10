# TL;DR

This contains files to build Enterprise Greenplum on Ubuntu.

# Examples

```
# produce an enterprise build with quicklz inside docker under /usr/local/greenplum-db-devel/
# create container image ubuntu_ent_build:16.04_dist
make

# check the quicklz actually working
# create container image ubuntu_ent_build:16.04_check
make check

# debug inside the container of last build failure
make debug

# clean the docker images, ubuntu_ent_build:*
make clean

# clean all other docker dangling containers and images
make docker-clean
```
