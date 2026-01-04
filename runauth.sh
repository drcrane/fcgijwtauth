#!/bin/sh
set -e
FCGIAPPNAME=authmain
if [ ! -d build ] ; then
	mkdir build
	cmake -GNinja -DCMAKE_BUILD_TYPE=Debug -Bbuild .
fi
ninja -C build/
if [ ! -d conf ] ; then
	mkdir conf
fi
if [ ! -f conf/e42_uk.jwks.json ] ; then
	build/jwks_creator https://testingid.e42.uk 947a627d87183f94388b39d71db6601679995a1f >> conf/e42_uk.jwks.json
fi
if [ ! -d appbin ] ; then
	mkdir appbin
fi
if [ -f appbin/${FCGIAPPNAME} ] ; then
	rm -f appbin/${FCGIAPPNAME}
fi
mv build/${FCGIAPPNAME} appbin/${FCGIAPPNAME}

FCGISOCKETDIR=/run/spawn-fcgi
if [ ! -d "${FCGISOCKETDIR}" ] ; then
doas mkdir "${FCGISOCKETDIR}"
doas chown nginx:nginx "${FCGISOCKETDIR}"
fi
doas spawn-fcgi -U nginx -G nginx -s "${FCGISOCKETDIR}/${FCGIAPPNAME}.sock-1" -n ./appbin/${FCGIAPPNAME}
