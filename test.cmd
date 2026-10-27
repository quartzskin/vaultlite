@echo off
setlocal
cd /d "%~dp0"
call build.cmd || exit /b 1
mkdir out\test
dir /s /b test\*.java > out\test-sources.txt
javac -encoding UTF-8 -cp out\classes -d out\test @out\test-sources.txt || exit /b 1
java -cp out\classes;out\test vaultlite.TestMain
