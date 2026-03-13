#!/bin/bash

mkdir -p bin
cd bin

# PhpGCC

echo "Installing phpggc"
git clone https://github.com/ambionics/phpggc 2>&1 || (echo "Error: cannot clone phpggc" && exit 1)

# Java

echo "Installing java 8"
wget -q "https://javadl.oracle.com/webapps/download/AutoDL?BundleId=251398_0d8f12bc927a4e2c9f8568ca567db4ee" -O /tmp/jre-8u431-linux-x64.tar.gz
tar -xzf /tmp/jre-8u431-linux-x64.tar.gz

echo "Installing JRE 1.8.0u20"
tar -xzf ../archives/jre-8u20-linux-x64.tar.gz

# Marshalsec
echo "Installing Marshalsec"

git clone https://github.com/mbechler/marshalsec /tmp/marshalsec/
cd /tmp/marshalsec/

mvn clean package -DskipTests

cd /build/bin/

if [ -f /tmp/marshalsec/target/marshalsec-0.0.3-SNAPSHOT-all.jar ]; then
    echo "Copying Marshalsec built from maven"
    cp /tmp/marshalsec/target/marshalsec-0.0.3-SNAPSHOT-all.jar .
else
    echo "Error: /tmp/marshalsec/target/marshalsec-0.0.3-SNAPSHOT-all.jar not found"
    exit 1
fi

if [ ! -f JRE8Exploit.jar ]; then
    echo "Installing JRE8Exploit jar"
    cp ../archives/JRE8Exploit-1.0-SNAPSHOT.jar JRE8Exploit.jar
    echo "JRE8Exploit jar installed"
fi

# ysoserial

if [ ! -f ysoserial-all.jar ]; then
    echo "Installing ysoserial"
    wget -q https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar 
    echo "Ysoserial installed"
fi

echo "Installing ysoserial.net"

url=`python3 -c "import requests; import json; print(json.loads(requests.get('https://api.github.com/repos/pwntester/ysoserial.net/releases').content)[0]['assets'][0]['browser_download_url'])"`

if [ $? -eq 0 ]; then
    echo "Downloading $url" 
    wget -q "$url" -O /tmp/yoserial.zip
else
    echo "Error: unable to download yoserial"
    exit 1
fi

unzip -q /tmp/yoserial.zip
if [ ! -f ./Release/ysoserial.exe ]; then
    echo "Error: no ysoserial.exe binary after unziping ysoserial.net zip"
    exit 1
fi

echo "Installing ruby payloads"
git clone https://github.com/GitHubSecurityLab/ruby-unsafe-deserialization/ 2>&1 || (echo "Error: cannot clone ruby payloads repo" && exit 1)

echo "Installing pickle"

# TODO pip3 install pickledb

echo "Installing Deser-Node"
git clone https://github.com/klezVirus/deser-node
cd deser-node
# TODO npm install yargs node-serialize funcster cryo
cd ..

echo "Everything seems to be installed now"
