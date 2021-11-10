#!/bin/sh
git fetch origin
sh tools/unittest.sh
retVal=$?
RED='\033[0;31m'
GREEN='\033[0;32m' 
Color_Off='\033[0m'
if [ $retVal -ne 0 ]; then
    echo "${RED} Check Error!"
else 
    git status
    echo "${GREEN} Check OK!"
fi
echo $Color_Off
exit $retVal