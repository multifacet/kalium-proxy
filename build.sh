#!/bin/bash

set -ex

sudo apt update

echo "Building lz4"
git clone https://github.com/lz4/lz4
pushd lz4
sudo make install
popd

echo "Building libzmq"
sudo apt remove libunwind-dev
sudo apt install -y \
    git build-essential libtool \
    pkg-config autotools-dev autoconf automake cmake \
    uuid-dev libpcre3-dev valgrind liblzma-dev
wget https://github.com/zeromq/libzmq/releases/download/v4.2.2/zeromq-4.2.2.tar.gz
tar -xvf zeromq-4.2.2.tar.gz
pushd zeromq-4.2.2
mkdir -p build
cd build
../configure
sudo make install -j$(nproc)
sudo ldconfig
popd

echo "Building czmq"
wget https://github.com/zeromq/czmq/releases/download/v4.2.0/czmq-4.2.0.tar.gz
tar -xvf czmq-4.2.0.tar.gz
pushd czmq-4.2.0
mkdir -p build
cd build
cmake ..
sudo make install
sudo ldconfig
popd

git checkout artifact
wget https://go.dev/dl/go1.19.linux-amd64.tar.gz
rm -rf /usr/local/go && tar -C /usr/local -xzf go1.19.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
go build -o seclambda
