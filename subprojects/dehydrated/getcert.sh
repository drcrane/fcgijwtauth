#!/bin/sh
set -e
cd subprojects/dehydrated/
if [ ! $(which bash) ] ; then
apk add --no-cache bash curl gawk sed grep diffutils openssl
fi
if [ ! -f dehydrated ] ; then
curl -O -L https://github.com/dehydrated-io/dehydrated/raw/refs/heads/master/dehydrated
chmod a+x dehydrated
fi
./dehydrated --config ./config --cron

