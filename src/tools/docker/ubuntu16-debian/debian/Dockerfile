FROM ubuntu_ent_build:16.04_dist

RUN apt-get update && \
    apt-get install -y software-properties-common \
                   debmake \
                   equivs \
                   git

COPY . /tmp/gpdb_src/debian/

WORKDIR /tmp/gpdb_src

RUN ./debian/build_debian.sh

WORKDIR /tmp
