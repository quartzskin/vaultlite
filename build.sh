#!/bin/sh
set -e
cd "$(dirname "$0")"
rm -rf out
mkdir -p out/classes
find src -name '*.java' > out/sources.txt
javac -encoding UTF-8 -Xlint:all,-serial -d out/classes @out/sources.txt
cp src/vaultlite/wordlist.txt out/classes/vaultlite/
jar --create --file out/vaultlite.jar --main-class vaultlite.Main -C out/classes .
echo built out/vaultlite.jar
