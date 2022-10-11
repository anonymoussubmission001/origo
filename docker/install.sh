#!/bin/bash

cd /root/origo/dependencies/jsnark-demo/JsnarkCircuitBuilder
wget https://www.bouncycastle.org/download/bcprov-jdk15on-159.jar
mkdir -p bin
javac -d bin -cp /usr/share/java/junit4.jar:bcprov-jdk15on-159.jar $(find ./src/* | grep ".java$")

# build check if 
cd /root/origo/dependencies/libsnark-demo
export LIBSNARK_BUILD_DIR="build"
if [ -d "$LIBSNARK_BUILD_DIR" ]; then
	rm -rf $LIBSNARK_BUILD_DIR
fi

# building libsnark
mkdir build && cd build && cmake .. -DMULTICORE=ON && make
cp -r /root/origo/dependencies/libsnark-demo/build/libsnark/jsnark_interface /root/origo/prover/zksnark_build/jsnark_interface/bin

