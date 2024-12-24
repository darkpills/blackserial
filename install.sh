#!/bin/bash

# going into the current script directory
CWD=`dirname $0`
cd $CWD/bin

command -v php >/dev/null 2>&1 || ( echo "Error: php not installed, install it first" && exit 1 )

if [ ! -d ./phpggc/ ]; then
    echo "Installing phpggc"
    git clone https://github.com/ambionics/phpggc 2>&1 || (echo "Error: cannot clone phpggc" && exit 1)
    if [ ! -f ./phpggc/phpggc ]; then
        echo "Error: no phpggc binary after cloning repository"
        exit 1
    fi
fi

javaVersion=`java -version 2>&1 | grep version | sed -e s#"^.*version \"\([0-9]\+\)\..*$"#"\1"#g`
if [ "$javaVersion" == "" ] || [ $javaVersion -gt 8 ] && [ ! -f ./jre1.8.0_431/bin/java ]; then
    echo "Installing java 8"
    wget -q "https://javadl.oracle.com/webapps/download/AutoDL?BundleId=251398_0d8f12bc927a4e2c9f8568ca567db4ee" -O jre-8u431-linux-x64.tar.gz  || ( cp ../archives/jre-8u431-linux-x64.tar.gz . )
    tar -xzf jre-8u431-linux-x64.tar.gz
    if [ ! -f ./jre1.8.0_431/bin/java ]; then
        echo "Error: no ./jre1.8.0_431/bin/java after untar"
        exit 1
    fi
fi

if [ ! -f ysoserial-all.jar ]; then
    echo "Installing ysoserial"
    wget -q https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar  || cp ../archives/ysoserial-all.jar .
    echo "Ysoserial installed"
fi

command -v wine >/dev/null 2>&1 || {
    echo "Installing wine, .net framework 4.8"
    if [ "$EUID" -ne 0 ]; then
        sudo apt install mono-complete wine winetricks -y
    else
        apt install mono-complete wine winetricks -y
    fi
    if [ "$DISPLAY" != "" ]; then
        winetricks -q dotnet48
        winetricks -q nocrashdialog
    else
        echo "warning: no display available, install dotnet48 manually"
    fi
}

if [ ! -d Release ]; then
    echo "Installing ysoserial.net"
    pip3 install requests
    url=`python3 -c "import requests; import json; print(json.loads(requests.get('https://api.github.com/repos/pwntester/ysoserial.net/releases').content)[0]['assets'][0]['browser_download_url'])"`
    if [ $? -eq 0 ]; then
        echo "Downloading $url" 
        wget -q "$url" || cp ../archives/ysoserial-*.zip .
    else
        cp ../archives/ysoserial-*.zip .
    fi
    unzip -q ysoserial-*.zip
    if [ ! -f ./Release/ysoserial.exe ]; then
        echo "Error: no ysoserial.exe binary after unziping ysoserial.net zip"
        exit 1
    fi
fi


command -v ruby >/dev/null 2>&1 || ( echo "Error: ruby not installed, install it first" && exit 1 )

if [ ! -d ruby-unsafe-deserialization ]; then
    echo "Installing ruby payloads"
    git clone https://github.com/GitHubSecurityLab/ruby-unsafe-deserialization/ 2>&1 || (echo "Error: cannot clone ruby payloads repo" && exit 1)
    if [ ! -d ruby-unsafe-deserialization/ ]; then
        echo "Error: no ruby-unsafe-deserialization directory after cloning repository"
        exit 1
    fi
fi

command -v python3 >/dev/null 2>&1 || command -v python >/dev/null 2>&1 || ( echo "Error: python3 not installed, install it first" && exit 1 )
python3 -c "import pickle;" 2>&1 || { 
    echo "Installing pickle";
    pip3 install pickledb; 
}

echo "Everything seems to be installed now"
