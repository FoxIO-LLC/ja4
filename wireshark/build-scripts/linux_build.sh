#!/bin/bash

VER=$1

if [ -x $VER ]
then echo "Enter a wireshark version (supported versions) => 4.0.3, 4.0.6, 4.0.10, 4.2.0"; exit
fi

echo "fetching wireshark sources with tag => tags/wireshark-$VER"
git clone -o upstream --branch wireshark-$VER https://gitlab.com/wireshark/wireshark.git --depth=5000
mv wireshark wireshark-$VER
cd wireshark-$VER
git checkout tags/wireshark-$VER

cp -r ../../linux ./plugins/epan/ja4
mv CMakeListsCustom.txt.example CMakeListsCustom.txt
sed -i "/plugins\/epan\/foo/c\plugins\/epan\/ja4" CMakeListsCustom.txt
mkdir build && cd build && cmake -G Ninja -DBUILD_wireshark=off ../
echo 'building using ninja...'
ninja -j8

FINAL=`find . -name "ja4.so"`

echo "Your JA4 Plugin is ready at $FINAL"

