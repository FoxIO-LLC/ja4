#!/bin/bash

mkdir -p build

cp ../source/* build/
cp CMakeLists.txt build/
cd build/

#cmake
cmake -D USER_INSTALL=ON .
make

