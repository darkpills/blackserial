# BlackSerial

A Blackbox Gadget Chain Serializer for Java (YSOSerial), PHP (PHPGGC), Python (Pickle), C#/.Net (YSOSerial.Net).

BlackSerial is a python wrapper for different gadget chain serializers. It is designed to be used during Blackbox pentesting or Bugbounty where you suspect a deserialisation user input but you don't have the code to identify or craft a gadget chain. 

It attempts to generate all possible chains, managing the burden of providing different input formats and options, and output the results in a file that can be used in Burp Intruder for instance.

It invent no new technique.

Features:
* Supported serializers: PHPGGC (PHP), YSOSerial (Java), YSOSerial.Net (C# .Net), Pickle (Python)

https://github.com/aludermin/ysoserial-wrapper

## Example

TODO

## Docker install

TODO

## Script local install

## Manual install

### phpggc

```
git clone https://github.com/ambionics/phpggc
```

### ysoserial

Install JRE8 in a local directory:
```
wget "https://javadl.oracle.com/webapps/download/AutoDL?BundleId=251398_0d8f12bc927a4e2c9f8568ca567db4ee" -O jre-8u431-linux-x64.tar.gz
tar -xzf jre-8u431-linux-x64.tar.gz
```

Download last release from officiel repo: https://github.com/frohoff/ysoserial/releases
```
wget https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar
```

Put `ysoserial-all.jar` in the same directory as `blackserial.py`

## pickle

Just install python pickle module:
```
pip3 install pickledb
```

### ysoserial.net

Under debian linux, use wine:
```
sudo apt update 
sudo apt install mono-complete wine winetricks -y
winetricks dotnet48
winetricks nocrashdialog
```

Download last release from officiel repo: https://github.com/pwntester/ysoserial.net/releases

Unzip it.

Make a unit test to see if everything is ok:
```
wine ./Release/ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -o base64 -c "ping 127.0.0.1"
```

## Kown issues:

The following gadgets fail to generate:
* YSOSerial.net: ActivitySurrogateDisableTypeCheck
* YSOSerial.net: PSObject 
* YSOSerial.net: ObjRef with formatter 'ObjectStateFormatter'
* YSOSerial.net: TypeConfuseDelegateMono
* YSOSerial.net: XamlAssemblyLoadFromFile with formatter 'SoapFormatter'
* PHPGGC: Symfony/RCE14 (PR opened)

## TODO

* test mode
* manage phar
* docker


## ⚠️ WARNING: LEGAL DISCLAIMER

This tool is intended for **educational and ethical use only**. The author is not liable for any illegal use or misuse of this tool. Users are solely responsible for their actions and must ensure they have explicit permission to scan the target systems.