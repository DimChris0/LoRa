#!/usr/bin/env python

import os
import sys
import csv
import json

OUTPUT_FORMATS = ('csv', 'tsv', 'json', 'yara', 'netflow', )

def getHandler(output_format):
	output_format = output_format.lower()
	if output_format not in OUTPUT_FORMATS:
		print("[WARNING] Invalid output format specified... using CSV")
		output_format = 'csv'

	handler_format = "OutputHandler_" + output_format
	handler_class = getattr(sys.modules[__name__], handler_format)

	return handler_class()

class OutputHandler(object):
	def print_match(self, fpath, page, name, match):
		pass

	def print_header(self, fpath):
		pass

	def print_footer(self, fpath):
		pass

	def print_error(self, fpath, exception):
		print "print error"
		print("[ERROR] %s" % (exception))

class OutputHandler_csv(OutputHandler):
	def __init__(self):
		self.csv_writer = csv.writer(sys.stdout)

	def print_match(self, fpath, page, name, match):
		self.csv_writer.writerow((fpath, page, name, match))

	def print_error(self, fpath, exception):
		self.csv_writer.writerow((fpath, '0', 'error', exception))

class OutputHandler_tsv(OutputHandler):
	def __init__(self):
		self.csv_writer = csv.writer(sys.stdout, delimiter = '\t')

	def print_match(self, fpath, page, name, match):
		self.csv_writer.writerow((fpath, page, name, match))

	def print_error(self, fpath, exception):
		self.csv_writer.writerow((fpath, '0', 'error', exception))

class OutputHandler_json(OutputHandler):
	def print_match(self, fpath, page, name, match):
		data = {
			'path' : fpath,
			'file' : os.path.basename(fpath),
			'page' : page,
			'type' : name,
			'match': match
		}

		print(json.dumps(data))

	def print_error(self, fpath, exception):
		data = {
			'path'      : fpath,
			'file'      : os.path.basename(fpath),
			'type'      : 'error',
			'exception' : exception
		}

		print(json.dumps(data))

class OutputHandler_yara(OutputHandler):
	def __init__(self):
		self.rule_enc = ''.join(chr(c) if chr(c).isupper() or chr(c).islower() or chr(c).isdigit() else '_' for c in range(256))

	def print_match(self, fpath, page, name, match):
		if name in self.cnt:
			self.cnt[name] += 1
		else:
			self.cnt[name] = 1
		rule_file = os.path.splitext(os.path.basename(fpath))[0].translate(self.rule_enc)
		string_id = "$%s%d" % (name, self.cnt[name])
		self.sids.append(string_id)
		string_value = match.replace('\\', '\\\\')
		# escape quote, error in one file
		#print("\t\t%s = \"%s\"" % (string_id, string_value.replace('"','\"')))
		with open("./signature-base/yara/" + rule_file + ".yar", 'a+') as f:
			f.write("\t\t%s = \"%s\"\n" % (string_id, string_value.replace('"','\"')))
			f.close()

	def print_header(self, fpath):
		rule_file= os.path.splitext(os.path.basename(fpath))[0].translate(self.rule_enc)
		rule_name = ''.join([i for i in rule_file if not i.isdigit()])
		print("rule %s" % (rule_name))
		#print("{")
		#print("\tstrings:")
		with open('./signature-base/yara/' + rule_file + ".yar", 'a+') as f:
			f.write("rule %s" % (rule_name) + "\n{\n\tstrings:\n")
			f.close()
		self.cnt = {}
		self.sids = []

	def print_footer(self, fpath):
		cond = ' or '.join(self.sids)
		rule_file = os.path.splitext(os.path.basename(fpath))[0].translate(self.rule_enc)
		#print("\tcondition:")
		#print("\t\t" + cond)
		#print("}")
		with open("./signature-base/yara/"+rule_file+".yar", 'a+') as f:
			f.write("\tcondition:\n" + "\t\t" + cond +"\n}")
			f.close()

class OutputHandler_netflow(OutputHandler):
	def __init__(self):
		print "host 255.255.255.255"

	def print_match(self, fpath, page, name, match):
		data = {
			'type' : name,
			'match': match
		}
		if data["type"] == "IP":
			print " or host %s " % data["match"]
