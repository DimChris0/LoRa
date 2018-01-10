#!/Python27/
# -*- coding: utf-8 -*-
#
# rastrea2r REST Server
#
# by Ismael Valenzuela @aboutsecurity / Foundstone (Intel Security)


#TODO: add pickle ?
#TODO: after downloading the signatures there are conflicts in yara where there are duplicate rules or syntax errors

from time import gmtime, strftime
from bottle import route, get, run, post, request
import codecs
import socket
import sys
import os
import re
import traceback
import yara
import stat
import psutil
import argparse
from subprocess import Popen, PIPE
from collections import Counter
from lib.lokilogger import *
from lib.helpers import *
from lib.doublepulsar import DoublePulsar
import wmi
import win32api
from win32com.shell import shell

sys.stdout = codecs.getwriter('utf8')(sys.stdout)

__author__ = ''
__version__ = '0.1'

platform == "windows"

# Computername
if platform == "linux" or platform == "osx":
    t_hostname = os.uname()[1]
else:
    t_hostname = os.environ['COMPUTERNAME']

serverlogger = LokiLogger(False, "LoRaServer-"+t_hostname+".log", t_hostname, None, 514, False, False, False,
                    platform=platform, caller='main')
loggers = {}

def get_application_path():
    try:
        if getattr(sys, 'frozen', False):
            application_path = os.path.dirname(os.path.realpath(sys.executable))
        else:
            application_path = os.path.dirname(os.path.realpath(__file__))
        if "~" in application_path and platform == "windows":
            # print "Trying to translate"
            # print application_path
            application_path = win32api.GetLongPathName(application_path)
        #if args.debug:
        #    logger.log("DEBUG", "Application Path: %s" % application_path)
        return application_path
    except Exception, e:
        serverlogger.log("ERROR", "Error while evaluation of application path")
        traceback.print_exc()
        sys.exit(1)

def walk_error(err):
    try:
        if "Error 3" in str(err):
            serverlogger.log('ERROR', removeNonAsciiDrop(str(err)))
        elif args.debug:
            print "Directory walk error"
            sys.exit(1)
    except UnicodeError, e:
        print "Unicode decode error in walk error message"


# Yara rule directories
yara_rule_directories = []
# Get application path
app_path = get_application_path()

yara_rule_directories.append(os.path.join(app_path, 'signature-base\\yara'))

# Set IOC path
ioc_path = os.path.join(app_path, "signature-base\\misc-txt")
filetype_magics_file = os.path.join(app_path, 'signature-base\\misc-txt\\file-type-signatures.txt')


def updateLoki(sigsOnly):
    serverlogger.log("INFO", "Starting separate updater process ...")
    pArgs = []

    # Updater
    if os.path.exists(os.path.join(get_application_path(), 'loki-upgrader.py')):
        pArgs.append('python')
        pArgs.append('loki-upgrader.py')
    elif os.path.exists(os.path.join(get_application_path(), 'loki-upgrader.exe')) and platform == "windows":
        pArgs.append('loki-upgrader.exe')
    else:
        serverlogger.log("ERROR", "Cannot find neither loki-upgrader.exe nor loki-upgrader.py in the current workign directory.")

    if sigsOnly:
        pArgs.append('--sigsonly')
        p = Popen(pArgs, shell=False)
        p.communicate()
    else:
        pArgs.append('--detached')
        Popen(pArgs, shell=False)



@post('/loginfo')
def index():
    loggers[request.forms.get('client')] = LokiLogger(False, "LoRa-"+request.forms.get('client')+".log", t_hostname, None, 514, False, False, False, platform=platform, caller='')



@post('/getrule')
def index():
    """ Method to serve a yara rule to the REST client. Rulename (filename) must exist on the same directory """

    client = request.forms.get('client')
    rulename = request.forms.get('rulename')
    #this is to check for the 'all' option
    if rulename is None:
        rulename = []
    yara_rules = []
    yaraRules = ""
    yaraRuleFile = ""
    dummy = ""

    # Check if signature database is present
    sig_dir = os.path.join(app_path, "./signature-base/")
    if not os.path.exists(sig_dir) or os.listdir(sig_dir) == []:
        (loggers[client]).log("INFO", "The 'signature-base' subdirectory doesn't exist or is empty. Trying to retrieve the signature database automatically.")
        updateLoki(sigsOnly=True)

    try:
        for yara_rule_directory in yara_rule_directories:
            if not os.path.exists(yara_rule_directory):
                continue

            (loggers[client]).log("INFO", "Processing YARA rules folder {0}".format(yara_rule_directory))
            for root, directories, files in os.walk(yara_rule_directory, onerror=walk_error, followlinks=False):
                for file in files:
                    try:
                        # yara rule file is in the set we want to apply OR set is empty
                        # which equals, add all the yara rules
                        if (file in rulename) or (not rulename):
                            # Full Path
                            yaraRuleFile = os.path.join(root, file)

                            # Skip hidden, backup or system related files
                            if file.startswith(".") or file.startswith("~") or file.startswith("_"):
                                continue

                            # Extension
                            extension = os.path.splitext(file)[1].lower()

                            # Test Compile
                            try:
                                compiledRules = yara.compile(yaraRuleFile, externals={
                                    'filename': dummy,
                                    'filepath': dummy,
                                    'extension': dummy,
                                    'filetype': dummy,
                                    'md5': dummy
                                })
                                (loggers[client]).log("INFO", "Initializing Yara rule %s" % file)
                            except Exception, e:
                                (loggers[client]).log("ERROR", "Error while initializing Yara rule %s" % file)
                                traceback.print_exc()
                                if (loggers[client]).debug:
                                    sys.exit(1)
                                continue

                            # Encrypted

                            if extension == ".yar" or extension == ".yara":
                                with open(yaraRuleFile, 'r') as rulefile:
                                    data = rulefile.read()
                                    yaraRules += data

                    except Exception, e:
                        (loggers[client]).log("ERROR", "Error reading signature file %s ERROR: %s" % yaraRuleFile)
                        if (loggers[client]).debug:
                            traceback.print_exc()
                            sys.exit(1)

    except Exception, e:
        (loggers[client]).log("ERROR", "Error reading signature folder %s" % yara_rule_directory)
        traceback.print_exc()
        if (loggers[client]).debug:
            traceback.print_exc()
            #sys.exit(1)
            return []

    return yaraRules


@post('/putfile')
def index():

    """ Method to post client data from file/dir scan to the REST server. Timestamps written in GMT """

    recivedt=strftime('%Y-%m-%d %H:%M:%S', gmtime())
    rulename = request.forms.get('rulename')
    filename = request.forms.get('filename')
    hostname = request.forms.get('hostname')
    module = request.forms.get('module')

    try:
        f=open("results.txt","a")
        f.write("%s, %s, %s, %s, %s\n\n" % (recivedt, hostname, rulename ,module, filename))
        f.close()
    except IOError:
        (loggers[client]).log( "ERROR", "The output file requested doesn't exist.")
    return""

@post('/putpid')
def index():

    """ Method to post client data from process memory scan to the REST server. Timestamps written in GMT """

    recivedt=strftime('%Y-%m-%d %H:%M:%S', gmtime())
    rulename = request.forms.get('rulename')
    processpath = request.forms.get('processpath')
    processpid = request.forms.get('processpid')
    hostname = request.forms.get('hostname')
    module = request.forms.get('module')

    try:
        f=open("results.txt","a")
        f.write("%s, %s, %s, %s, %s, %s\n\n" % (recivedt, hostname, rulename, module, processpath, processpid))
        f.close()
    except IOError:
        (loggers[client]).log( "ERROR", "The output file requested doesn't exist")
    return""


@post('/getfilenameiocs')
def index():
    client = request.forms.get('client')
    filename_iocs = {}
    counter = 0
    try:
        for ioc_filename in os.listdir(ioc_path):
            if 'filename' in ioc_filename:
                with codecs.open(os.path.join(ioc_path, ioc_filename), 'r', encoding='utf-8') as file:
                    lines = file.readlines()

                    # Last Comment Line
                    last_comment = ""

                    for line in lines:
                        try:
                            # Empty
                            if re.search(r'^[\s]*$', line):
                                continue

                            # Comments
                            if re.search(r'^#', line):
                                last_comment = line.lstrip("#").lstrip(" ").rstrip("\n")
                                continue

                            # Elements with description
                            if ";" in line:
                                line = line.rstrip(" ").rstrip("\n\r")
                                row = line.split(';')
                                regex = row[0]
                                score = row[1]
                                if len(row) > 2:
                                    regex_fp = row[2]
                                desc = last_comment

                                # Catch legacy lines
                                if not score.isdigit():
                                    desc = score        # score is description (old format)
                                    score = 60          # default value

                            # Elements without description
                            else:
                                regex = line

                            # Replace environment variables

                            regex = replaceEnvVars(regex)
                            # OS specific transforms
                            regex = transformOS(regex, platform)

                            # If false positive definition exists
                            regex_fp_comp = None
                            if 'regex_fp' in locals():
                                # Replacements
                                regex_fp = replaceEnvVars(regex_fp)
                                regex_fp = transformOS(regex_fp, platform)
                                # String regex as key - value is compiled regex of false positive values
                                regex_fp_comp = regex_fp

                            if regex_fp_comp == None:
                                fioc = {'regex': regex, 'score': score, 'description': desc, 'regex_fp': "null"}
                            else:
                                fioc = {'regex': regex, 'score': score, 'description': desc, 'regex_fp': regex_fp_comp}

                            filename_iocs["a" + str(counter)] = fioc
                            counter += 1
                        except Exception, e:
                            (loggers[client]).log("ERROR", "Error reading line: %s" % line)
                            traceback.print_exc()
                            return None
    except Exception, e:
        traceback.print_exc()
        (loggers[client]).log("ERROR", "Error reading File IOC file: %s" % ioc_filename)
        (loggers[client]).log("ERROR", "Please make sure that you cloned the repo or downloaded the sub repository: See "
                            "https://github.com/Neo23x0/Loki/issues/51")
        return None

    return filename_iocs




@post('/initC2Server')
def index():
    client = request.forms.get('client')
    c2_server = {}
    try:
        for ioc_filename in os.listdir(ioc_path):
            try:
                #TODO: fix to search all files 1)insert c2 to all files 2)change the below to search all files and not only with c2 in name
                if 'c2' in ioc_filename:
                    with codecs.open(os.path.join(ioc_path, ioc_filename), 'r', encoding='utf-8') as file:
                        lines = file.readlines()

                        for line in lines:
                            try:
                                # Comments and empty lines
                                if re.search(r'^#', line) or re.search(r'^[\s]*$', line):
                                    continue

                                # Split the IOC line
                                row = line.split(';')
                                if len(row) > 1:
                                    c2 = row[0]
                                    comment = row[1].rstrip(" ").rstrip("\n")
                                else:
                                    c2 = row[0]

                                # Check length
                                if len(c2) < 4:
                                    (loggers[client]).log("INFO", "C2 server definition is suspiciously short - will not add %s" %c2)
                                    continue

                                # Add to the LOKI iocs
                                c2_server[c2.lower()] = comment

                            except Exception,e:
                                print 3
                                (loggers[client]).log("ERROR", "Cannot read line: %s" % line)
                                return None
            except OSError, e:
                (loggers[client]).log("ERROR", "No such file or directory")
    except Exception, e:
        traceback.print_exc()
        (loggers[client]).log("ERROR", "Error reading Hash file: %s" % ioc_filename)

    return c2_server



@post('/initHashIocs')
def index():
    client = request.forms.get('client')
    hashes_md5 = {}
    hashes_sha1 = {}
    hashes_sha256 = {}
    false_hashes = {}
    dictOfDicts = {}
    counter = 0

    try:
        for ioc_filename in os.listdir(ioc_path):
            if 'hash' in ioc_filename:
                with codecs.open(os.path.join(ioc_path, ioc_filename), 'r', encoding='utf-8') as file:
                    lines = file.readlines()

                    for line in lines:
                        try:
                            if re.search(r'^#', line) or re.search(r'^[\s]*$', line):
                                continue
                            row = line.split(';')
                            if len(row) > 1:
                                hash = row[0]
                                comment = row[1].rstrip(" ").rstrip("\n")
                            else:
                                hash = row[0]
                                comment = ""
                            # Empty File Hash
                            if hash == "d41d8cd98f00b204e9800998ecf8427e" or \
                               hash == "da39a3ee5e6b4b0d3255bfef95601890afd80709" or \
                               hash == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855":
                                continue
                            # Else - check which type it is
                            if len(hash) == 32:
                                hashes_md5[hash.lower()] = comment
                            if len(hash) == 40:
                                hashes_sha1[hash.lower()] = comment
                            if len(hash) == 64:
                                hashes_sha256[hash.lower()] = comment
                            if 'falsepositive' in ioc_filename:
                                false_hashes[hash.lower()] = comment

                        except Exception,e:
                            print 1
                            (loggers[client]).log("ERROR", "Cannot read line: %s" % line)

        dictOfDicts["md5"] = hashes_md5
        dictOfDicts["sha1"] = hashes_sha1
        dictOfDicts["sha256"] = hashes_sha256
        dictOfDicts["false"] = false_hashes

        return dictOfDicts

    except Exception, e:
        (loggers[client]).log("ERROR", "Error reading Hash file: %s" % ioc_filename)
        traceback.print_exc()


@post('/initFiletypeMagics')
def index():
    client = request.forms.get('client')
    max_filetype_magics = 0
    filetype_magics = {}
    result = {}
    try:
        with open(filetype_magics_file, 'r') as config:
            lines = config.readlines()

        for line in lines:
            try:
                if re.search(r'^#', line) or re.search(r'^[\s]*$', line) or ";" not in line:
                    continue

                ( sig_raw, description ) = line.rstrip("\n").split(";")
                sig = re.sub(r' ', '', sig_raw)

                if len(sig) > max_filetype_magics:
                    max_filetype_magics = len(sig)

                # print "%s - %s" % ( sig, description )
                filetype_magics[sig] = description

            except Exception,e:
                print 2
                (loggers[client]).log("ERROR", "Cannot read line: %s" % line)

        result["len"] = max_filetype_magics
        result["file"] = filetype_magics

        return result
    except Exception, e:
        # if logger.debug:
        traceback.print_exc()
        (loggers[client]).log("ERROR", "reading Hash file: %s" % filetype_magics_file)
        return None



################################## MAIN ########################################
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='LoRa - Simple IOC Scanner')
    parser.add_argument('-s', help='Server address', metavar='server-address', default='localhost')
    parser.add_argument('-p', help='Port', metavar='', default='8080')
    parser.add_argument('--update', action='store_true', default=False, help='Update the signatures from the "signature-base" sub repository')

    args = parser.parse_args()
    server_address = args.s
    server_port = args.p
    if args.update:
        updateLoki(True)


    run(server='cherrypy', host=server_address, port=8080)
