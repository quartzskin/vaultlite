@echo off
setlocal
cd /d "%~dp0"
if exist out rmdir /s /q out
mkdir out\classes
dir /s /b src\*.java > out\sources.txt
javac -encoding UTF-8 -Xlint:all,-serial -d out\classes @out\sources.txt || exit /b 1
copy /y src\vaultlite\wordlist.txt out\classes\vaultlite\ >nul
jar --create --file out\vaultlite.jar --main-class vaultlite.Main -C out\classes . || exit /b 1
echo built out\vaultlite.jar
