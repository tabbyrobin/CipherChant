#!/usr/bin/env bash
# Get python2 and bananaphone module installed.
set -e

# Intended to be run in a VM or docker container etc. Dont use on your
# main system except at your own risk.  Written for Debian 10.

apt-get update
apt-get install -y apt-utils
apt-get upgrade -y
apt-get install -y git python-pip python3-pip fish
# rm -rf /var/lib/apt/lists/*

# having recent pip fixes some wheel not supported errors (e.g. for
# poetry installing regex module wheel)
# python2 -m pip install --upgrade pip
# python3 -m pip install --upgrade pip

pushd ~
git clone https://github.com/tabbyrobin/bananaphone

pushd bananaphone
pip2 install --user -e . # -e: makes it an editable install

popd && popd

pip2 install --user fire click # dependencies for bp_wrapper.py

# ok done
