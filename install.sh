#!/bin/bash

[ -d ./phpggc/ ] || {
    echo "Installing phpggc"
    git clone https://github.com/ambionics/phpggc 2>&1 || { echo "Error: can't clone phpggc repository"; exit 1; }
    if [ ! -f ./phpggc/phpggc ]; then
        echo "Error: no phpggc binary after cloning repository"
        exit 1
    fi
}

javaVersion=`java -version 2>&1 | grep version | sed -e s#"^.*version \"\([0-9]\+\)\..*$"#"\1"#g`
if [ "$javaVersion" == "" ] || [ $javaVersion -gt 8 ]; then
    echo "Installing java 8"
    wget "https://javadl.oracle.com/webapps/download/AutoDL?BundleId=251398_0d8f12bc927a4e2c9f8568ca567db4ee" -O jre-8u431-linux-x64.tar.gz  || { echo "Error: can't download JRE8"; exit 1; }
    tar -xzf jre-8u431-linux-x64.tar.gz
    if [ ! -f ./jre1.8.0_431/bin/java ]; then
        echo "Error: no ./jre1.8.0_431/bin/java after untar"
        exit 1
    fi
fi

[ -f ysoserial-all.jar ] || {
    echo "Installing ysoserial"
    wget https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar  || { echo "Error: can't download ysoserial-all.jar"; exit 1; }
    echo "Ysoserial already installed"
}

command -v wine >/dev/null 2>&1 || {
    echo "Installing wine, .net framework 4.8"
    sudo apt update 
    sudo apt install mono-complete wine winetricks -y
    winetricks dotnet48
    winetricks nocrashdialog
}

[ -d Release ] || {
    echo "Installing ysoserial.net"
    url=`python3 -c "import requests; import json; print(json.loads(requests.get('https://api.github.com/repos/pwntester/ysoserial.net/releases').content)[0]['assets'][0]['browser_download_url'])"`
    if [ $? -ne 0 ]; then
        echo "Error: can't download ysoserial.net release info"
        exit 1
    fi
    echo "Downloading $url" 
    wget "$url" || { echo "Error: can't download ysoserial.net release"; exit 1; }
    unzip ysoserial-*.zip
    if [ ! -f ./Release/ysoserial.exe ]; then
        echo "Error: no ysoserial.exe binary after unziping ysoserial.net zip"
        exit 1
    fi
}

python3 -c "import pickle;" 2>&1 || { 
    echo "Installing pickle";
    pip3 install pickledb; 
}

echo "Everything seems to be installed now"
