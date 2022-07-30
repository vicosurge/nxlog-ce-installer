#!/bin/bash

NAME=nxlog
TOPDIR=`pwd`/rpmbuild
DISTRO="${JENKINS_BUILD_DISTRO:-default}"

#Check what OS and version we have, if not given
check_os() {
    if [ -f /etc/os-release ]; then
      # run in a subshell, so all the variables will be lost except DISTRO
      DISTRO=$(
      source /etc/os-release
      echo "`echo $ID | tr '[[:upper:]]' '[[:lower:]]'``echo $VERSION_ID | cut -d. -f1`"
      )
    elif [ -f /etc/redhat-release ]; then
        DISTRO=rhel`cut -d. -f1 /etc/redhat-release | rev | cut -d' ' -f1`
    else
        DISTRO=generic
    fi
}

[[ ${DISTRO} =~ ^(generic|sles15|sles12|sles11|rhel7|rhel8|rhel6)$ ]] || check_os

echo "INFO: build distribution is ${DISTRO}"

# uncomment the lines beginning with #@DISTRO@
perl -pi -e "{
 s/#@([a-z0-9-]*\|)*${DISTRO}(\|[a-z0-9-]*)*@//;   # uncomment the distro specific parts
}" $NAME.spec.in

rm -rf $TOPDIR/BUILD

VERSION=`ls -d nxlog-ce-*.*.*.tar.gz | head -n 1 | sed 's/nxlog-ce-\(.*\).tar.gz/\1/'`
MKDIRLIST="$TOPDIR/BUILD/$NAME-root $TOPDIR/RPMS $TOPDIR/SOURCES $TOPDIR/SPECS $TOPDIR/SRPMS"

for dirn in $MKDIRLIST; do
    mkdir -p $dirn
done

cat $NAME.spec.in | sed s/@VERSION@/$VERSION/ > $NAME.spec

if test x$SPEC_FILE = 'x'; then
    SPEC_FILE="$NAME.spec"
fi

RPM_SPEC="$TOPDIR/SPECS/$SPEC_FILE"

cp nxlog-*.tar.gz $TOPDIR/SOURCES/
cp $SPEC_FILE $RPM_SPEC

cd "$TOPDIR/SPECS/"

rpmbuild -bb --define="_topdir $TOPDIR" --define="_tmppath $TOPDIR/tmp" --buildroot=$TOPDIR/BUILD/$NAME-root $SPEC_FILE

cd ${TOPDIR}/../
rm -f nxlog-*.tar.gz

ARCH=`arch`
if [ $ARCH = "i686" ]; then
  ARCH='i386'
fi

mv ${TOPDIR}/RPMS/${ARCH}/*.rpm ./

echo "FILENAME: nxlog-ce-${VERSION}_${DISTRO}_${ARCH}.rpm" > module_list.txt

for i in `ls nxlog*.rpm | grep -v -- '-debuginfo-' | sort`; do
    echo ${i} >> module_list.txt
    rpm -qlp ${i} | sed 's/^.*\/modules\/\(input\|output\|extension\|processor\)\/\([^/ ]*\)\.so.*$/ \1: \2/;tx;d;:x' | sort >> module_list.txt
    echo "" >> module_list.txt
done


#echo "Cleaning up tempfiles"
#echo "rm -r $TOPDIR"
#rm -r $TOPDIR



