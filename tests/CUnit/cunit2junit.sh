#!/bin/sh

for f in `ls -al *-Results.xml | cut -d" " -f9`; do
    if [ ! -f cunit2junit/$f ]; then
        xsltproc --stringparam suitename Libsklog -o cunit2junit/$f cunit-to-junit.xsl $f
        echo OK!
    fi
done
