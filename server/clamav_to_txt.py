#!/usr/bin/env python
# encoding: utf-8
#
# Tested on Linux (Ubuntu), Windows XP/7, and Mac OS X
#
"""
clamav_to_yara.py

Created by Matthew Richard on 2010-03-12.
Copyright (c) 2010 __MyCompanyName__. All rights reserved.
"""

import sys
import os
import re
from optparse import OptionParser

def main():
        parser = OptionParser()
        parser.add_option("-f", "--file", action="store", dest="filename",
                     type="string", help="scanned FILENAME, if \"ALL\" is given then all files are parsed")
        parser.add_option("-v", "--verbose", action="store_true", default=False,
                                        dest="verbose", help="verbose")
        parser.add_option("-s", "--search", action="store", dest="search",
                        type="string", help="search filter", default="")

        (opts, args) = parser.parse_args()

        if opts.filename == None:
                parser.print_help()
                parser.error("You must supply a filename!")
        if not os.path.isfile(opts.filename) and opts.filename != "ALL":
                parser.error("%s does not exist" % opts.filename)


        hextype = 0
        clam_sigs_folder = './signature-base/clamav-unofficial-sigs/'
        output_hex_file = "./signature-base/misc-txt/ClamAV_hex_sigs.txt"
        output_hash_file = "./signature-base/misc-txt/ClamAV_hashes_sigs.txt"

        if opts.filename == "ALL":
            filelist = []
            for file_ in os.listdir(clam_sigs_folder):
                if file_.endswith(".ndb") or file_.endswith(".hdb") or file_.endswith(".hsb"):
                    filelist.append(os.path.join(clam_sigs_folder, file_))
        else:
            filelist = [opts.filename]

        for file_ in filelist:
            rules = {}
            output = ""
            data = open(file_, 'rb').readlines()

            if (file_.endswith(".cvd") or file_.endswith(".cld")) and data[0].find("ClamAV") == 0:
                print "It seems you're passing a compressed database."
                print "Try using sigtool -u to decompress first."
                return

            print "[+] Read %d lines from %s" % (len(data), file_)

            # ClamAV signatures are one per line
            for line in data:
                if file_.endswith(".ndb"):
                    # signature format is
                    # name:sigtype:offset:signature
                    hextype = 1
                    try:
                            vals = line.split(':')
                            if len(vals) < 4 or len(vals) > 6:
                                    print "**ERROR reading ClamAV signature file**"
                                    continue
                            name = vals[0]
                            sigtype = vals[1]
                            offset = vals[2]
                            signature = vals[3]
                    except:
                            print "**ERROR reading ClamAV signature file**"
                            continue
                elif file_.endswith(".hdb") or file_.endswith(".hsb"):
                    # signature format is
                    # signature:sigtype:name:offset
                    hextype = 0
                    try:
                            vals = line.split(':')
                            if len(vals) < 3 or len(vals) > 5:
                                    print "**ERROR reading ClamAV signature file**"
                                    continue
                            name = vals[2]
                            sigtype = vals[1]
                            signature = vals[0]
                    except:
                            print "**ERROR reading ClamAV signature file**"
                            continue


                # if specified, only parse rules that match a search criteria
                if opts.search in name:

                        # sanitize rule name for YARA compatability
                        # YARA does not allow non-alphanumeric chars besides _
                        rulename_regex = re.compile('(\W)')
                        rulename = rulename_regex.sub('_', name)

                        # and cannot start with a number
                        rulename_regex = re.compile('(^[0-9]{1,})')
                        rulename = rulename_regex.sub('', rulename)

                        # if the rule doesn't exist, create a dict entry
                        if rulename not in rules:
                                rules[rulename] = []

                        # handle the ClamAV style jumps
                        # {-n} is n or less bytes
                        jump_regex = re.compile('(\{-(\d+)\})')
                        signature = jump_regex.sub('{0-\g<2>}', signature)

                        # {n-} is n or more bytes
                        jump_regex = re.compile('(\{(\d+)-\})')
                        matches = jump_regex.findall(signature)

                        if matches:
                                for match in matches:
                                        #print "\t\tfound %s" % (match[1])
                                        start = int(match[1])
                                        jump_regex = re.compile('(\{(%d)-\})' % (start))
                                        if (start < 256):
                                                #print "\t\t\tfound short jump of len %d" % (start)
                                                signature = jump_regex.sub('[0-\g<2>]', signature)
                                        else:
                                                #print "\t\t\tfound long jump, replacing with '*'"
                                                signature = jump_regex.sub('*', signature)

                        # {n-m} is n to m bytes
                        # need to make sure it's not bigger than 255,
                        # and the high bound cannot exceed 255
                        # if it is we'll treat it like a '*'
                        jump_regex = re.compile('(\{(\d+)-(\d+)\})')
                        matches = jump_regex.findall(signature)

                        if matches:
                                for match in matches:
                                        #print "\t\tfound %s - %s" % (match[1], match[2])
                                        start = int(match[1])
                                        end = int(match[2])
                                        jump_regex = re.compile('(\{(%d)-(%d)\})' % (start, end))
                                        if (end - start == 0):
                                                if opts.verbose:
                                                        print "\t**Skip nothing, impossible!**"
                                                signature = jump_regex.sub('', signature)
                                        elif (end - start < 256) and (end < 256):
                                                #print "\t\t\tfound short jump of len %d" % (end - start)
                                                signature = jump_regex.sub('[\g<2>-\g<3>]', signature)
                                        else:
                                                #print "\t\t\tfound long jump, replacing with '*'"
                                                signature = jump_regex.sub('*', signature)

                        # {n} bytes
                        # here we must also enforce the 255 byte maximum jump
                        # that YARA can handle
                        jump_regex = re.compile('(\{(\d+)\})')
                        matches = jump_regex.findall(signature)

                        if matches:
                                for match in matches:
                                        #print "\t\tfound %s" % (match[1])
                                        start = int(match[1])
                                        jump_regex = re.compile('(\{(%d)\})' % (start))
                                        if start < 256:
                                                #print "\t\t\tfound short jump of len %d" % (start)
                                                signature = jump_regex.sub('[\g<2>]', signature)
                                        else:
                                                #print "\t\t\tfound long jump, replacing with '*'"
                                                signature = jump_regex.sub('*', signature)

                        # translate the '*' operator into a pair of signatures
                        # with an 'and'
                        if '*' in signature:
                                for part in signature.split('*'):
                                        if part[0] != '(':
                                                rules[rulename].append(part.strip())
                        else:
                                if signature[0] != '(':
                                        rules[rulename].append(signature.strip())

            for rule in rules.keys():
                            """
                            detects = ''
                            conds = "\t"
                            x = 0
                            for detect in rules[rule]:
                                    detects += "\t$a%d = { %s }\r\n" % (x, detect)
                                    if x > 0:
                                            conds += " and "
                                    conds += "$a%d" % (x)
                                    x += 1
                            if detects == '':
                                    if opts.verbose:
                                            print "\t**Found empty rule %s, skipping**" % rule
                                    continue
                            else:
                                    output += yara_rule % (rule, detects, conds)
                            """
                            detects = ''
                            for detect in rules[rule]:
                                    detects += "%s\n" % detect
                            if detects == '':
                                    if opts.verbose:
                                            print "\t**Found empty rule %s, skipping**" % rule
                                    continue
                            else:
                                    output += detects

            if len(output) > 0:
                    outfile = ""
                    if hextype:
                        outfile = output_hex_file
                    else:
                        outfile = output_hash_file
                    print "\r\n[+] Wrote %d rules to %s\r\n" % (len(rules), outfile)
                    fout = open(outfile, 'ab+')
                    fout.write(output)
                    fout.close()
            else:
                    print "\r\n**Could not find any signatures to convert!!!**\r\n"

if __name__ == '__main__':
        print "\n" + '#' * 75
        print "\t" + "ClamAV Signature Extractor for .ndb, .hdb and .hsb file type only"
        print "\n" + '#' * 75, "\n"

        main()
