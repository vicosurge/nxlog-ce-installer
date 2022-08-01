#!/bin/bash
# The following script can be used in stand alone mode
# with the intent of creating all the required folders
# as well as compiling NXLog CE
# Create all required folders
NX_ETC=/usr/local/etc
NX_VAR=/usr/local/var
mkdir $NX_ETC
mkdir $NX_ETC/nxlog
cp configuration/nxlog.conf $NX_ETC/nxlog
mkdir $NX_VAR
mkdir $NX_VAR/run
mkdir $NX_VAR/run/nxlog
touch $NX_VAR/run/nxlog/nxlog.pid
mkdir $NX_VAR/spool
mkdir $NX_VAR/spool/nxlog

# Compile NXLog
# Note: Currently you have to install the required libraries
# yourself but the final intent is for this script to cover
# most of the larger Distros
DISTRO=$(cat /etc/issue)
NX_CE=$(ls | grep nxlog-ce-)
NX_FOLDER=nxlog-ce-3
if [[ "$DISTRO" =~ Debian|Ubuntu ]]
then
	echo "This is a Debian based distro, installing libraries"
	apt install build-essential libapr1-dev libpcre3-dev libssl-dev libexpat1-dev -y
elif [[ "$DISTRO" =~ Alpine ]]
then
	echo "This is an Alpine based distro, installing libraries"
	apk add --no-cache make g++ tar apr-dev openssl-dev pcre-dev libdbi-dev openssl expat-dev zlib-dev perl perl-dev file python3-dev -y
elif [ -e /etc/rocky-release ]
# While we get the right packages it does not work
# due to what seems to be an automake conflict
then
	DISTRO=Rocky
	echo "This is a Rocky Linux based distro, installing libraries"
	yum install gcc apr-devel pcre-devel openssl-devel expat-devel make automake libtool -y
elif [ -e /etc/centos-release ]
then
	DISTRO=CentOS
	echo "This is a CentOS based distro, installing libraries"
	yum install gcc apr-devel pcre-devel openssl-devel expat-devel make automake libtool -y
fi

# Cover process of decompressing and compiling
mkdir $NX_FOLDER
tar -xf $NX_CE -C $NX_FOLDER --strip-components=1
cd $NX_FOLDER
./autogen.sh
make
make install

# Cleaning up after installation
cd ..
rm -vR $NX_FOLDER
if [[ "$DISTRO" =~ Debian|Ubuntu ]]
then
        apt remove build-essential libpcre3-dev libexpat1-dev -y
elif [[ "$DISTRO" =~ Alpine ]]
then
	apk del make g++ openssl-dev libdbi-dev expat-dev zlib-dev perl-dev
elif [[ "$DISTRO" =~ Rocky|CentOS ]]
then
	yum remove apr-devel pcre-devel openssl-devel expat-devel
fi
echo "Configuration file can be found at /usr/local/etc/nxlog"
