# BlackSerial

Blackbox Gadget Chain Serializer for Java, PHP, Python, C#/.Net.

BlackSerial is a python wrapper for gadget chain serializers: PHPGGC, YSOSerial, YSOSerial.Net and provides Pickle gadgets. It attempts to generate all possible chains, managing the burden of different gadget chain input formats and options, and output the results in a file that can be used in Burp Intruder for instance.

Features:
* Supported serializers: PHPGGC (PHP), YSOSerial (Java), YSOSerial.Net (C# .Net), Pickle (Python)

https://github.com/aludermin/ysoserial-wrapper

## Example

TODO

## Docker install

TODO

## Manual install

### phpggc

TODO

### ysoserial

Download last release from officiel repo: https://github.com/frohoff/ysoserial/releases
```
wget https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar
```

Put `ysoserial-all.jar` in the same directory as `blackserial.py`

Install JDK8 and if not possible JDK11:
```

```


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
* PHPGGC: Symfony/RCE14

## TODO

* test mode
* manage phar
* docker