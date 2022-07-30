#!/bin/sh

DEBDIR="../../debian"
VERSION=`cd ../.. && ./version.sh|sed s/\:/_/`
DISTRO='default';
if test x`which lsb_release` != "x"; then
     DISTROUC="`lsb_release -i -s`-`lsb_release -c -s`";
 DISTRO="`echo $DISTROUC|tr '[:upper:]' '[:lower:]'`";
else
    echo "please install the lsb-release package";
    exit 1;
fi

ARCH=`dpkg --print-architecture`

(
    
#    if echo $VERSION | grep \: >/dev/null; then
#	echo "refusing to build package, changes must be committed to svn first"
#	exit 1
#    fi

     if test -f control.$DISTRO; then 
	cp -f control.$DISTRO control
     else
	echo "control.$DISTRO not found, using control.default to build package"
	cp -f control.default control
     fi

    RELEASE_DATE=`LC_ALL=en_US date "+%a, %d %b %Y %T %z"`
    rm -f changelog
    echo "nxlog-ce ($VERSION) unstable; urgency=low" >changelog
    echo "" >>changelog
    echo "  * SVN snapshot release." >>changelog
    echo "" >>changelog
    echo " -- Botond Botyanszki <boti@nxlog.org>  $RELEASE_DATE" >>changelog
    echo "" >>changelog
    cat changelog.skel >>changelog

    cd ../..
    ln -s -f packaging/debian debian

#    export DEB_BUILD_OPTIONS=nostrip,noopt
    dpkg-buildpackage -b -rfakeroot || exit 2;
    if test "x$RUN_TESTS" = "x1";
	then make check || exit 2;
    fi

)
RC=$?

if [ "$RC" -eq "1" ]; then
	exit 1
fi

(
cd ../..
FILES="";

for i in `cat packaging/debian/files | grep -v -e .buildinfo -e dbg| awk '{print $1}' | sort`; do
      # skip empty deb packages
      if test `stat --printf="%s" ../$i` -ge 2000; then
          FILES="${FILES} ../${i}"
      else
          # Check if needed
          rm -f $i
      fi
    done

filename="nxlog-ce_${VERSION}_$( echo ${DISTRO} | tr "-" "_")_${ARCH}.deb"
printf "FILENAME: ${filename}\n" > ../module_list.txt

for my_file in `echo "${FILES}" | sort`; do
        echo ${filename}  >> ../module_list.txt
        #need to catch the exit code from dpkg
        (s=/tmp/.$$_`hexdump -n 2 -e '/2 "%u"' /dev/urandom`;((dpkg -c ${my_file}; echo $?>$s) | (sed 's/^.*\/modules\/\(input\|output\|extension\|processor\)\/\([^/ ]*\)\.so.*$/ \1: \2/;tx;d;:x') | (sort >> ../module_list.txt)); exit $(cat $s; rm $s)) || printf "make module_list.txt failed\nMARK: UNSTABLE"
        echo "" >> ../module_list.txt
    done
)


RC=$?
rm -f $DEBDIR
if test -f changelog; then
    rm -f changelog
fi

rm -f control
exit $RC
