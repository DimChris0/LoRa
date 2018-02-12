#!/Python27/
# -*- coding: iso-8859-1 -*-
# -*- coding: utf-8 -*-
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

from iocparser.iocp import Parser
import sys
import lxml.objectify
from openpyxl import load_workbook
import csv

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
                       # Disabled until yara-python supports the hash.md5() function again
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

    def __init__(self, debug, logger, application_path):
        self.debug = debug
        self.logger = logger
        self.application_path = get_application_path()

    def walk_error(err):
        try:
            if "Error 3" in str(err):
                serverlogger.log('ERROR', removeNonAsciiDrop(str(err)))
            elif args.debug:
                print "Directory walk error"
                sys.exit(1)
        except UnicodeError, e:
            print "Unicode decode error in walk error message"


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
                    sigDir = os.path.join(self.application_path, r'signature-base/')
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
                            self.logger.log("INFO", "New signature file: %s" % sigName)

                        # Extract file
                        source = zipUpdate.open(zipFilePath)
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


    def threatExpert(self):
        tE = threatExpertParser()
        tE.parsePages()


    def extractFromFiles(self):
        for root, directories, files in os.walk(unicode(r'./signature-base'), onerror=walk_error, followlinks=False):
            for dirr in directories:
                if dirr == 'pdf':
                    filel = checkToParse(dirr, self.application_path)
                    parser = Parser.Parser(None, 'pdf', True, 'pdfminer', 'yara', None)
                    parser.parse(self.application_path + "\\signature-base\\pdf\\")
                elif dirr == 'openiocs':
                    ffile = checkToParse(dirr, self.application_path)
                    if ffile:
                        self.parseOpenIocs(ffile)
                elif dirr == "excel":
                    ffile = checkToParse(dirr, self.application_path)
                    if ffile:
                        self.parseExcel(ffile)
                elif dirr == 'csv':
                    ffile = checkToParse(dirr, self.application_path)
                    if ffile:
                        self.parseCSV(ffile)
        # parse the text format last as we append new data to those files from the extraction from excel, csv and openioc files
        parser = Parser.Parser(None, 'txt', True, 'pdfminer', 'yara', None)
        parser.parse(r'./signature-base/misc-txt')



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
                        writeToFile(cell.value, "hashes.txt")
                    elif 'domain' in headerColVal or 'ip' in headerColVal or 'c2' in headerColVal or 'url' in headerColVal:
                        writeToFile(cell.value, "c2-iocs.txt")
                    elif 'filename' in headerColVal or 'file name' in headerColVal:
                        writeToFile(cell.value, "filename-iocs.txt")
                    elif 'indicator type' in headerColVal:
                        cellVal = cell.value.lower()
                        if 'url' in cellVal or 'c2' in cellVal or 'ip' in cellVal or 'domain' in cellVal:
                            writeToFile(row[colnum].value, "c2-iocs.txt")
                        elif 'md5' in cellVal or 'sha' in cellVal:
                            writeToFile(cell.value, "hashes.txt")
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
                    writeToFile(col, "hashes.txt")
                elif 'domain' in headerColVal or 'ip' in headerColVal or 'c2' in headerColVal:
                    writeToFile(col, "c2-iocs.txt")
                elif 'filename' in headerColVal or 'file name' in headerColVal:
                    writeToFile(col, "filename-iocs.txt")
                elif 'indicator type' in headerColVal:
                    colVal = col.lower()
                    if 'url' in colVal or 'c2' in colVal:
                        writeToFile(row[colnum], "c2-iocs.txt")
                    elif 'md5' in colVal or 'sha' in colVal:
                        writeToFile(col, "hashes.txt")
                colnum += 1
            rownum += 1
        ifile.close()




    def parseOpenIocs(self, openIOC_file):
        ioco=lxml.objectify.parse( r'./signature-base/openiocs/' + openIOC_file)
        root=ioco.getroot()

        for node in root.iter():
            search = node.attrib.get('search')

            if search == "DnsEntryItem/RecordName" or search == "PortItem/remoteIP":
                with open(r'./signature-base/misc-txt/c2_ips_domains.txt', "a+") as iocfile:
                    iocfile.write(node.getnext() + "\n")
                iocfile.close()
            elif search == "FileItem/Md5sum" or search == "FileItem/Sha1sum" or search == "FileItem/Sha256sum":
                with open(r'./signature-base/misc-txt/hashes.txt', "a+") as iocfile:
                    iocfile.write(node.getnext() + "\n")
                iocfile.close()
            # I add the ProcessItem here because they are scan_processes searches the filename_iocs
            elif search == "FileItem/FileName" or search == "ProcessItem/path" or search == "ProcessItem/name":
                with open(r'./signature-base/misc-txt/filenames.txt', "a+") as iocfile:
                    iocfile.write(node.getnext() + "\n")
                iocfile.close()



def writeToFile(data, fileName):
    try:
    	with open("./signature-base/misc-txt/" + fileName, 'a+') as f:
    		f.write("%s\n" % data)
    		f.close()
    except Exception as e:
        print("Error with file I/O")
        traceback.print_exc()


# check if the file already exists as .yar -> not parsing it again
def checkToParse(dirr, app_path):
    file_list = []
    for root, directories, files in os.walk(unicode("./signature-base/" + dirr), onerror=walk_error, followlinks=False):
        for ffile in files:
            #check if there is the yara rule for this file first
            if not os.path.exists(app_path + r'./signature-base/yara/' + ffile[:-3] + 'yar') and not os.path.exists(app_path + r'./signature-base/yara/' + ffile[:-4] + 'yara'):
                file_list.append(ffile)

    return file_list


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

    if args.sigs:
        logger.log("INFO", "Updating Signatures ...")
        updater.update_signatures()

    updater.extractFromFiles()
    logger.log("INFO", "Update complete")

    if args.detached:
        logger.log("INFO", "Press any key to return ...")

    sys.exit(0)
