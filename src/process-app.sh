#!/bin/bash

apktool d -r -b $1.apk
rm $1.apk
mv $1 data/
find "data/$1" -type f -not -name "*.smali" -exec rm -f {} \;
# find "data/$1" -type f -name "*.smali" -exec mv '{}' "data/$1/" \;
# cd "data/$1"
# rm -R -- */

