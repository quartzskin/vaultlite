#!/bin/sh
set -e
cd "$(dirname "$0")"
./build.sh
mkdir -p out/test
find test -name '*.java' > out/test-sources.txt
javac -encoding UTF-8 -cp out/classes -d out/test @out/test-sources.txt
java -cp out/classes:out/test vaultlite.TestMain
