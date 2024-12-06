import subprocess
import tempfile
import logging
import os

class Serializer:

    usage = 'usage'

    def __init__(self, bin, chainOpts):
        self.bin = bin
        self.chainOpts = chainOpts

    def exec(self, arguments, rawResult=False):
        results = ""
        try:
            cmd = f'{self.bin} {arguments}'
            logging.debug(f"{cmd}")
            fullCommand = ['/bin/bash', '-c', cmd]
            processResult = subprocess.run(fullCommand, capture_output=True)
        except subprocess.CalledProcessError as e:
            processResult = e

        if rawResult:
            return processResult

        if processResult.returncode == 0:
            results = processResult.stdout.decode('ascii')
        elif processResult.stderr != None:
            results = processResult.stderr.decode('ascii')
        elif processResult.stdout != None:
            results += processResult.stdout.decode('ascii')
        return results

    def exists(self):
        out = self.exec('-h')
        if self.usage in out:
            return True
        else:
            logging.error(out)
            return False
    
    def getFileContentOrCode(self, code):
        if os.path.exists(code):
            with open(code) as f:
                content = f.read()
        else:
            content = code
        return content
    
    def createTemporaryFile(self):
        logging.debug(f"Creating temporary file for payload")
        with tempfile.NamedTemporaryFile(delete=False) as tempFilePointer:
            pass
        logging.debug(f"Temporary file created: {tempFilePointer.name}")
        return tempFilePointer

    def payload(self, chainName, chainArgs):
        return self.exec(f"{chainName} {chainArgs}", rawResult=True)
        

