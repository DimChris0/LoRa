#!/Python27/
# -*- utf-8 -*-
#
#  LOKI Upgrader

try:
    from urllib2 import urlopen, HTTPError
except ImportError:
    from urllib.request import urlopen #For python 3.5
import json
import zipfile
import shutil
try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO
import os
import argparse
import traceback
from sys import platform as _platform
from sets import Set
from iocparser.iocp import Parser
import sys
import lxml.objectify
from openpyxl import load_workbook
import csv
import string
from threatExpertParser import *

# Win32 Imports
if _platform == "win32":
    try:
        import wmi
        import win32api
        from win32com.shell import shell
    except Exception, e:
        platform = "linux"  # crazy guess


from lib.lokilogger import *

# Platform
platform = ""
if _platform == "linux" or _platform == "linux2":
    platform = "linux"
elif _platform == "darwin":
    platform = "osx"
elif _platform == "win32":
    platform = "windows"

class LoRaUpdater(object):

    UPDATE_URL_SIGS = ["https://github.com/Neo23x0/signature-base/archive/master.zip",
                       # Disabled until yara-python supports the hash.md5() function again, it is a bug
                       # "https://github.com/SupportIntelligence/Icewater/archive/master.zip"
                       "https://github.com/makflwana/IOCs-in-CSV-format/archive/master.zip",
                       "https://github.com/citizenlab/malware-indicators/archive/master.zip",
                       "https://github.com/eset/malware-ioc/archive/master.zip",
                       "https://github.com/fireeye/iocs/archive/master.zip",
                       "https://github.com/jasonmiacono/IOCs/archive/master.zip",
                       "https://github.com/pan-unit42/iocs/archive/master.zip",
                       "https://github.com/kbandla/APTnotes/archive/master.zip"
                       ]

    UPDATE_URL_LORA = ""
    printable = set(string.printable)

    def __init__(self, debug, logger, application_path):
        self.debug = debug
        self.logger = logger
        self.application_path = get_application_path()
        self.newFiles = Set([])

    def update_signatures(self):
        try:
            for sig_url in self.UPDATE_URL_SIGS:
                # Downloading current repository
                try:
                    self.logger.log("INFO", "Downloading %s ..." % sig_url)
                    response = urlopen(sig_url)
                except Exception as e:
                    traceback.print_exc()
                    self.logger.log("ERROR", "Error downloading the signature database - check your Internet connection")
                    sys.exit(1)

                # Preparations
                try:
                    sigDir = os.path.join(self.application_path, 'signature-base\\')
                    for outDir in ['', 'openiocs', 'yara', 'csv', 'misc-txt', 'excel', 'pdf']:
                        fullOutDir = os.path.join(sigDir, outDir)
                        if not os.path.exists(fullOutDir):
                            os.makedirs(fullOutDir)
                except Exception as e:
                    traceback.print_exc()
                    self.logger.log("ERROR", "Error while creating the signature-base directories")
                    sys.exit(1)

                # Read ZIP file
                try:
                    zipUpdate = zipfile.ZipFile(StringIO(response.read()))
                    for zipFilePath in zipUpdate.namelist():
                        sigName = os.path.basename(zipFilePath)

                        if zipFilePath.endswith("/"):
                            continue
                        self.logger.log("DEBUG", "Extracting %s ..." % zipFilePath)
                        #for some characters not recognisable in unicode format
                        sigName = ''.join(filter(lambda x: x in string.printable, sigName))

                        sigName = re.sub('[<>:?"/\|*]', '', sigName)
                        if zipFilePath.endswith(".txt"):
                            targetFile = os.path.join(sigDir, "misc-txt", sigName)
                        elif zipFilePath.endswith(".yara") or zipFilePath.endswith(".yar"):
                            targetFile = os.path.join(sigDir, "yara", sigName)
                        elif zipFilePath.endswith(".csv"):
                            targetFile = os.path.join(sigDir, "csv", sigName)
                        elif zipFilePath.endswith(".ioc"):
                            targetFile = os.path.join(sigDir, "openiocs", sigName)
                        elif zipFilePath.endswith(".xls") or zipFilePath.endswith(".xlsx"):
                            targetFile = os.path.join(sigDir, "excel", sigName)
                        elif zipFilePath.endswith(".pdf"):
                            targetFile = os.path.join(sigDir, "pdf", sigName)
                        else:
                            continue

                        # New file
                        if not os.path.exists(targetFile):
                            self.newFiles.add(sigName)
                            self.logger.log("INFO", "New signature file: %s" % sigName)

                        # Extract file
                        source = zipUpdate.open(zipFilePath)
                        print targetFile
                        target = file(targetFile, "wb")
                        with source, target:
                            shutil.copyfileobj(source, target)

                except Exception as e:
                    traceback.print_exc()
                    self.logger.log("ERROR", "Error while extracting the signature files from the download package")
                    sys.exit(1)

        except Exception as e:
            if self.debug:
                traceback.print_exc()
            return False
        return True


    def update_lora(self):
        try:
            # Downloading the info for latest release
            try:
                self.logger.log("INFO", "Checking location of latest release %s ..." % self.UPDATE_URL_LOKI)
                response_info = urlopen(self.UPDATE_URL_LOKI)
                data = json.load(response_info)
                # Get download URL
                zip_url = data['assets'][0]['browser_download_url']
                self.logger.log("INFO", "Downloading latest release %s ..." % zip_url)
                response_zip = urlopen(zip_url)
            except Exception as e:
                traceback.print_exc()
                self.logger.log("ERROR", "Error downloading the lora update - check your Internet connection")
                sys.exit(1)

            # Read ZIP file
            try:
                zipUpdate = zipfile.ZipFile(StringIO(response_zip.read()))
                for zipFilePath in zipUpdate.namelist():
                    if zipFilePath.endswith("/") or "/config/" in zipFilePath or "/loki-upgrader.exe" in zipFilePath:
                        continue

                    source = zipUpdate.open(zipFilePath)
                    targetFile = "/".join(zipFilePath.split("/")[1:])

                    self.logger.log("INFO", "Extracting %s ..." %targetFile)

                    try:
                        target = file(targetFile, "wb")
                        with source, target:
                                shutil.copyfileobj(source, target)
                    except Exception as e:
                        self.logger.log("ERROR", "Cannot extract %s" % targetFile)
                        if self.debug:
                            traceback.print_exc()

            except Exception as e:
                if self.debug:
                    traceback.print_exc()
                self.logger.log("ERROR", "Error while extracting the signature files from the download package")
                sys.exit(1)

        except Exception as e:
            if self.debug:
                traceback.print_exc()
            return False
        return True

    # Source code in threatExpertParser.py in same folder
    def threatExpert(self, from_page, to_page, level):
        tE = ThreatExpertParser(from_page, to_page, level)
        tE.parsePages()


    def extractFromFiles(self):
        pdf_parser = Parser.Parser(None, 'pdf', True, 'pdfminer', 'yara', None)
        txt_parser = Parser.Parser(None, 'txt', True, 'pdfminer', 'yara', None)
        while len(self.newFiles) > 0:
            f = self.newFiles.pop()
            if '.pdf' == f[-4:]:
                pdf_parser.parse(self.application_path + "\\signature-base\\pdf\\" + f)
            elif '.ioc' == f[-4:]:
                self.parseOpenIocs(f)
            elif ('.xlsx' == f[-5:]) or ('.xls' == f[-4:]):
                self.parseExcel(f)
            elif '.csv' == f[-4:]:
                self.parseCSV(f)
            elif '.txt' == f[-4:]:
                txt_parser.parse(self.application_path + "\\signature-base\\misc-txt\\" + f)
        # this code parses the pdfs inside the folder problematic pdfs, even though there is no difference
        # as the rules created are empty
        # for filename in os.listdir(self.application_path + "\\signature-base\\problematicPDFs\\"):
        #     if "new" in filename:
        #         print filename
        #         pdf_parser.parse(self.application_path + "\\signature-base\\problematicPDFs\\" + filename)



    def parseExcel(self, excel_file):
        wb = load_workbook(filename = self.application_path + r'./signature-base/excel/' + excel_file, read_only=True)
        # grab the active worksheet
        ws = wb.active
        rownum = 0
        for row in ws.rows:
            # Save header row.
            if rownum == 0:
                header = row
            colnum = 0
            for cell in row:
                if header[colnum].value != None:
                    headerColVal = header[colnum].value.lower()
                    if 'sha' in headerColVal or 'md5' in headerColVal:
                        writeToFile(cell.value, excel_file + "_hashes.txt")
                        self.newFiles.add(excel_file + "_hashes.txt")
                    elif 'domain' in headerColVal or 'ip' in headerColVal or 'c2' in headerColVal or 'url' in headerColVal:
                        writeToFile(cell.value, excel_file + "_c2.txt")
                        self.newFiles.add(excel_file + "_c2.txt")
                    elif 'filename' in headerColVal or 'file name' in headerColVal:
                        writeToFile(cell.value, excel_file + "_filename.txt")
                        self.newFiles.add(excel_file + "_filename.txt")
                    elif 'indicator type' in headerColVal:
                        cellVal = cell.value.lower()
                        if 'url' in cellVal or 'c2' in cellVal or 'ip' in cellVal or 'domain' in cellVal:
                            writeToFile(row[colnum].value, excel_file + "_c2.txt")
                            self.newFiles.add(excel_file + "_c2.txt")
                        elif 'md5' in cellVal or 'sha' in cellVal:
                            writeToFile(cell.value, excel_file + "_hashes.txt")
                            self.newFiles.add(excel_file + "_hashes.txt")
                    colnum += 1
            rownum += 1


    def parseCSV(self, csv_file):
        # rU stands for:In a Python with universal newline support open() the mode parameter can also be "U",
        # meaning "open for input as a text file with universal newline interpretation". Mode "rU" is also allowed,
        # for symmetry with "rb"
        ifile = open(r'./signature-base/csv/' + csv_file, 'rU')
        reader = csv.reader(ifile)
        rownum = 0
        for row in reader:
            # Save header row.
            if rownum == 0:
                header = row
            colnum = 0
            for col in row:
                headerColVal = header[colnum].lower()
                if 'sha' in headerColVal or 'md5' in headerColVal:
                    writeToFile(col, csv_file[:-3] + "_hashes.txt")
                    self.newFiles.add(csv_file[:-3] + "_hashes.txt")
                elif 'domain' in headerColVal or 'ip' in headerColVal or 'c2' in headerColVal:
                    writeToFile(col, csv_file[:-3] + "_c2.txt")
                    self.newFiles.add(csv_file[:-3] + "_c2.txt")
                elif 'filename' in headerColVal or 'file name' in headerColVal:
                    writeToFile(col, csv_file[:-3] + "_filename.txt")
                    self.newFiles.add(csv_file[:-3] + "_filename.txt")
                elif 'indicator type' in headerColVal:
                    colVal = col.lower()
                    if 'url' in colVal or 'c2' in colVal:
                        writeToFile(row[colnum], csv_file[:-3] + "_c2.txt")
                        self.newFiles.add(csv_file[:-3] + "_c2.txt")
                    elif 'md5' in colVal or 'sha' in colVal:
                        writeToFile(col, csv_file[:-3] + "_hashes.txt")
                        self.newFiles.add(csv_file[:-3] + "_hashes.txt")
                colnum += 1
            rownum += 1
        ifile.close()




    def parseOpenIocs(self, openIOC_file):

        ioco=lxml.objectify.parse( r'./signature-base/openiocs/' + openIOC_file)
        root=ioco.getroot()

        for node in root.iter():
            search = node.attrib.get('search')
            if search == "DnsEntryItem/RecordName" or search == "PortItem/remoteIP":
                with open(r'./signature-base/misc-txt/' + openIOC_file[:-3] + "_c2_.txt", "a+") as iocfile:
                    iocfile.write(node.getnext() + "\n")
                iocfile.close()
                self.newFiles.add(openIOC_file[:-3] + "_c2_.txt")
            elif search == "FileItem/Md5sum" or search == "FileItem/Sha1sum" or search == "FileItem/Sha256sum":
                with open(r'./signature-base/misc-txt/' + openIOC_file[:-3] + "_hashes_.txt", "a+") as iocfile:
                    iocfile.write(node.getnext() + "\n")
                iocfile.close()
                self.newFiles.add(openIOC_file[:-3] + "_hashes_.txt")
            # I add the ProcessItem here because they are scan_processes searches the filename_iocs
            elif search == "FileItem/FileName" or search == "ProcessItem/path" or search == "ProcessItem/name":
                with open(r'./signature-base/misc-txt/' + openIOC_file[:-3] + "_filename_.txt", "a+") as iocfile:
                    iocfile.write(node.getnext() + "\n")
                iocfile.close()
                self.newFiles.add(openIOC_file[:-3] + "_filename_.txt")

def walk_error(err):
    try:
        if "Error 3" in str(err):
            serverlogger.log('ERROR', removeNonAsciiDrop(str(err)))
        elif args.debug:
            print "Directory walk error"
            sys.exit(1)
    except UnicodeError, e:
        print "Unicode decode error in walk error message"


def writeToFile(data, fileName):
    try:
    	with open("./signature-base/misc-txt/" + fileName, 'a+') as f:
    		f.write("%s\n" % data)
    		f.close()
    except Exception as e:
        print("Error with file I/O")
        traceback.print_exc()



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
    except Exception as e:
        print("Error while evaluation of application path")
        traceback.print_exc()


if __name__ == '__main__':

    # Parse Arguments
    parser = argparse.ArgumentParser(description='LoRa - Upgrader')
    parser.add_argument('-l', help='Log file', metavar='log-file', default='LoRa-upgrade.log')
    parser.add_argument('--nolog', action='store_true', help='Don\'t write a local log file', default=False)
    parser.add_argument('--debug', action='store_true', default=False, help='Debug output')
    parser.add_argument('--detached', action='store_true', default=False, help=argparse.SUPPRESS)
    # parser.add_argument('--sigsonly', action='store_true', help='Update the signatures only', default=False)
    # parser.add_argument('--progonly', action='store_true', help='Update the program files only', default=False)

    parser.add_argument('--threxp', action='store_true', default=False, help='Search and parse the threat expert website for signatures')
    parser.add_argument('-f', action='store', default=1, help='The number of the first page signatures will be downloaded, default is 1')
    parser.add_argument('-t', action='store', default=10, help='The number of the last page signatures will be downloaded, default is 10')
    parser.add_argument('-v', action='store', default=3, help='The minimum threat level of the signatures will be downloaded from a scale 0-5, default is 3, e.g. with threat level 3 signatures with level >=3 will be downloaded')

    args = parser.parse_args()

    # Computername
    if platform == "windows":
        t_hostname = os.environ['COMPUTERNAME']
    else:
        t_hostname = os.uname()[1]

    # Logger
    logger = LokiLogger(args.nolog, args.l, t_hostname, '', '', False, False, args.debug, platform=platform, caller='upgrader')

    # Update LoRa
    updater = LoRaUpdater(args.debug, logger, get_application_path())


    logger.log("INFO", "Updating Signatures ...")
    updater.update_signatures()

    if args.threxp:
        logger.log("INFO", "Downloading signatures from Threat Expert ...")
        updater.threatExpert(int(args.f), int(args.t), int(args.v))

    updater.extractFromFiles()
    logger.log("INFO", "Update complete")

    if args.detached:
        logger.log("INFO", "Press any key to return ...")

    sys.exit(0)
