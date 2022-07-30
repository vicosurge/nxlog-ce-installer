#!/bin/bash
# The following script can be used in stand alone mode
# with the intent of creating all the required folders
# as well as compiling NXLog CE
# Create all required folders
mkdir /usr/local/etc
mkdir /usr/local/etc/nxlog
touch /usr/local/etc/nxlog/nxlog.conf
mkdir /usr/local/var
mkdir /usr/local/var/run
mkdir /usr/local/var/run/nxlog
touch /usr/local/var/run/nxlog/nxlog.pid
mkdir /usr/local/var/spool
mkdir /usr/local/var/spool/nxlog

# Compile NXLog
# Note: Currently you have to install the required libraries
# yourself but the final intent is for this script to cover
# most of the larger Distros
distro=$(cat /etc/issue)
nxlog_ce=$(ls | grep nxlog-ce-)
nxlog_folder=nxlog-ce-3
if [[ "$distro" =~ Debian|Ubuntu ]]
then
	echo "This is a Debian based distro, installing libraries"
	apt install build-essential libapr1-dev libpcre3-dev libssl-dev libexpat1-dev
elif [[ "$distro" =~ Alpine ]]
then
	echo "This is an Alpine based distro, installing libraries"
	apk add --no-cache make g++ tar apr-dev openssl-dev pcre-dev libdbi-dev openssl expat-dev zlib-dev perl perl-dev file python3-dev
fi

# Cover process of decompressing and compiling
cp nxlog.conf /usr/local/etc/nxlog
mkdir $nxlog_folder
tar -xf $nxlog_ce -C $nxlog_folder --strip-components=1
cd $nxlog_folder
./configure
make
make install

# Cleaning up after installation
if [[ "$distro" =~ Debian|Ubuntu ]]
then
        apt remove build-essential libpcre3-dev libexpat1-dev -y
elif [[ "$distro" =~ Alpine ]]
then
	apk del make g++ openssl-dev libdbi-dev expat-dev zlib-dev perl-dev
fi
echo "Configuration file can be found at /usr/local/etc/nxlog"
