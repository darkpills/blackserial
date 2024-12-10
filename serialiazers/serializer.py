import subprocess
import tempfile
import logging
import os
import sys

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
        elif processResult.stderr != b'':
            results = processResult.stderr.decode('ascii')
        elif processResult.stdout != b'':
            results += processResult.stdout.decode('ascii')
        return results

    def exists(self):
        out = self.exec('-h 2>&1')
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
    
    def createTemporaryFile(self, suffix=None, dir=None):
        logging.debug(f"Creating temporary file for payload")
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=suffix, dir=dir) as tempFilePointer:
                pass
            logging.debug(f"Temporary file created: {tempFilePointer.name}")
            return tempFilePointer
        except Exception as e:
            logging.error(f"Cannot create temporary file: {e}")
            return None


    def payload(self, chainName, chainArgs):
        return self.exec(f"{chainName} {chainArgs}", rawResult=True)
    
    def getOutputFilepath(self, chainUniqueId):
        output = os.path.abspath(self.chainOpts.output)
        if self.chainOpts.one_file_per_payload:
            if os.path.isdir(output):
                filePath = os.path.join(output, chainUniqueId+'.txt')
            else:
                directory = os.path.dirname(output)
                filename = os.path.basename(output)
                filenameWithoutExt, extension = os.path.splitext(filename)
                filePath = os.path.join(directory, chainUniqueId+extension)
        else:
            if os.path.isdir(output):
                filePath = os.path.join(output, 'payloads.txt')
            else:
                filePath = output
        return filePath
    
    def output(self, chainUniqueId, payload):
        if not self.chainOpts.output or self.chainOpts.output == '-':
            f = sys.stdout.buffer
            f.write(payload)
        else:
            filePath = self.getOutputFilepath(chainUniqueId)
            f = open(filePath, 'ab')
            f.write(payload)
            f.close()

        
        

