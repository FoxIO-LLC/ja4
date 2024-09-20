#!/bin/bash
# Copyright (c) 2024, FoxIO, LLC.
# All rights reserved.
# Patent Pending
# JA4 is Open-Source, Licensed under BSD 3-Clause
# JA4+ (JA4S, JA4H, JA4L, JA4X, JA4SSH, JA4T) are licenced under the FoxIO License 1.1. For full license text, see the repo root.

VER=$1

if [ -x $VER ]
then echo "Enter a wireshark version (supported versions) => 4.0.3, 4.0.6, 4.0.10, 4.2.0"; exit
fi

if [ ! -d wireshark-$VER ]
  then
    echo "fetching wireshark sources with tag => tags/wireshark-$VER"
    git clone -o upstream --branch wireshark-$VER https://gitlab.com/wireshark/wireshark.git --depth=5000
    mv wireshark wireshark-$VER
    cd wireshark-$VER
    git checkout tags/wireshark-$VER

    # Prep for macos using wireshark's prep script
    ./tools/macos-setup-brew.sh
    brew install qt5
  else
    cd wireshark-$VER
fi

rm -rf ./plugins/epan/ja4
cp -r ../../source ./plugins/epan/ja4

if [ ! -d build ]; then
    mkdir build 
fi

cd build && cmake -DCUSTOM_PLUGIN_SRC_DIR=plugins/epan/ja4 -DBUILD_wireshark=off ../
echo 'building using make...'
make -j8

if [ ! -d ../../../../ja4-plugin ]; then  
  mkdir ../../../../ja4-plugin
fi

cp `find . -name ja4.so` ../../../../ja4-plugin/
echo "Your JA4 Plugin is ready at" `find . -name ja4.so`


