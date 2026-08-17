#!/bin/sh
set -e
FCGIAPPNAME=filemannospawn
if [ ! -d build ] ; then
	mkdir build
	cmake -GNinja -DCMAKE_BUILD_TYPE=Debug -Bbuild .
fi
ninja -C build/ ${FCGIAPPNAME}
if [ ! -d appbin ] ; then
	mkdir appbin
fi
if [ -f appbin/${FCGIAPPNAME} ] ; then
	rm -f appbin/${FCGIAPPNAME}
fi
mv build/${FCGIAPPNAME} appbin/${FCGIAPPNAME}
doas chown root:root appbin/${FCGIAPPNAME}
doas chmod 4755 appbin/${FCGIAPPNAME}

FCGISOCKETDIR=/run/spawn-fcgi
if [ ! -d "${FCGISOCKETDIR}" ] ; then
doas mkdir "${FCGISOCKETDIR}"
doas chown nginx:nginx "${FCGISOCKETDIR}"
fi
doas chmod og+rwx /run/spawn-fcgi
doas chmod og+rwx ${FCGISOCKETDIR}/${FCGIAPPNAME}.sock
#exec ./appbin/${FCGIAPPNAME} -U nginx -G nginx "${FCGISOCKETDIR}/${FCGIAPPNAME}.sock"
exec ./appbin/${FCGIAPPNAME} -N "${FCGISOCKETDIR}/${FCGIAPPNAME}.sock"
