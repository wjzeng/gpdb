#!/bin/bash

echo "Caching password..."
sudo -K
sudo true;

if hash brew 2>/dev/null; then
	echo "Homebrew is already installed!"
else
	echo "Installing Homebrew..."
	ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
fi

brew install bash-completion
brew install conan
brew install cmake # gporca
brew install xerces-c #gporca
brew install libyaml # enables `--enable-mapreduce`
brew install libevent # gpfdist
brew install apr # gpfdist
brew install apr-util # gpfdist
brew install zstd
brew install pkg-config
brew link --force apr
brew link --force apr-util

brew install python3

echo 127.0.0.1$'\t'$HOSTNAME | sudo tee -a /etc/hosts

# OS settings
sudo sysctl -w kern.sysv.shmmax=2147483648
sudo sysctl -w kern.sysv.shmmin=1
sudo sysctl -w kern.sysv.shmmni=64
sudo sysctl -w kern.sysv.shmseg=16
sudo sysctl -w kern.sysv.shmall=524288
sudo sysctl -w net.inet.tcp.msl=60

sudo sysctl -w net.local.dgram.recvspace=262144
sudo sysctl -w net.local.dgram.maxdgram=16384
sudo sysctl -w kern.maxfiles=131072
sudo sysctl -w kern.maxfilesperproc=131072
sudo sysctl -w net.inet.tcp.sendspace=262144
sudo sysctl -w net.inet.tcp.recvspace=262144
sudo sysctl -w kern.ipc.maxsockbuf=8388608

sudo tee -a /etc/sysctl.conf << EOF
kern.sysv.shmmax=2147483648
kern.sysv.shmmin=1
kern.sysv.shmmni=64
kern.sysv.shmseg=16
kern.sysv.shmall=524288
net.inet.tcp.msl=60

net.local.dgram.recvspace=262144
net.local.dgram.maxdgram=16384
kern.maxfiles=131072
kern.maxfilesperproc=131072
net.inet.tcp.sendspace=262144
net.inet.tcp.recvspace=262144
kern.ipc.maxsockbuf=8388608
EOF

# Create GPDB destination directory
sudo mkdir /usr/local/gpdb
sudo chown $USER:admin /usr/local/gpdb

# Configure
cat >> ~/.bashrc << EOF
ulimit -n 65536 65536  # Increases the number of open files
export PGHOST="$(hostname)"
EOF

cat << EOF

================

Please source greenplum_path.sh after compiling database, then

pip3 install --user -r python-dependencies.txt

EOF
