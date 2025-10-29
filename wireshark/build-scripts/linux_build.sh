#!/bin/bash
# Copyright (c) 2024, FoxIO, LLC.
# All rights reserved.
# Patent Pending
# JA4 is Open-Source, Licensed under BSD 3-Clause
# JA4+ (JA4S, JA4H, JA4L, JA4X, JA4SSH, JA4T) are licenced under the FoxIO License 1.1. For full license text, see the repo root.

VER=$1

if [ -z $VER ]
then echo "Enter a wireshark version (e.g. wireshark-4.4.0, v4.6.0)"; exit
fi

if [ ! -d $VER ]
then
	echo "fetching wireshark sources with tag => tags/$VER"
	git clone -o upstream --branch $VER https://gitlab.com/wireshark/wireshark.git --depth=5000
	mv wireshark $VER
fi

cd $VER
git checkout tags/$VER
rm -rf ./plugins/epan/ja4
cp -r ../../source ./plugins/epan/ja4
mv CMakeListsCustom.txt.example CMakeListsCustom.txt
sed -i "/plugins\/epan\/foo/c\plugins\/epan\/ja4" CMakeListsCustom.txt
./tools/debian-setup.sh

if [ ! -d build ]
then
	mkdir build 
fi

cd build && cmake -G Ninja -DBUILD_wireshark=off ../
echo 'building using ninja...'
ninja -j8

FINAL=`find . -name "ja4.so"`

echo "Your JA4 Plugin is ready at $FINAL"

