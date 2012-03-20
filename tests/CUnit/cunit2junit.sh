#!/bin/sh

for f in `ls -al *-Results.xml | cut -d" " -f9`; do
    xsltproc --stringparam suitename Libsklog -o cunit2junit/$f cunit-to-junit.xsl $f
done
