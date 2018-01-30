# LoRa

Collecting & Hunting for Indicators of Compromise (IOC)
The two specialiced scanners [LOKI](https://github.com/Neo23x0/Loki) and [Rastrea2r](https://github.com/aboutsecurity/rastrea2r)
have been merged into a new generic IOC scanner called LoRa. By using a client/server RESTful API, it can also hunt for IOCs
on disk and memory across multiple systems using YARA rules. The server is the one responsible for finding, downloading the IOCs
and then serving them as yara rules to the clients. The clients recieve the data and proceeds to scan its system and produce the
reports of the result. The server side is inside the server folder(lora_server.py) and the client side inside win32 folder(lora_win32.py).


Detection is based on four detection methods:
1. File Name IOC
	 Regex match on full file path/name
2. Yara Rule Check
	 Yara signature match on file data and process memory
3. Hash check
	 Compares known malicious hashes (MD5, SHA1, SHA256) with scanned files
4. C2 Back Connect Check
	 Compares process connection endpoints with C2 IOCs

Additional Checks:

1. Regin filesystem check (via --reginfs)
2. Process anomaly check (based on [Sysforensics](http://goo.gl/P99QZQ))
3. SWF decompressed scan
4. SAM dump check
5. DoublePulsar check - tries to detect DoublePulsar backdoor on port 445/tcp and 3389/tcp


## How-To Run LoRa and Analyse the Reports

### Run

  - Run it once to retrieve the latest signature base repository
  - Provide the folder to a target system that should be scanned: removable media, network share, folder on target system
  - Open a command line "cmd.exe" as Administrator and run it from there (you can also run LoRa without administrative privileges but some checks will be disabled and relevant objects on disk will not be accessible)


### Reports

  - The resulting report will show a GREEN, YELLOW or RED result line.
  - Please analyse the findings yourself by:
    1. uploading non-confidential samples to [Virustotal.com](https://www.virustotal.com)
    2. Search the web for the filename
    3. Search the web for keywords from the rule name (e.g. EQUATIONGroupMalware_1 > search for "Equation Group")
    4. Search the web for the MD5 hash of the sample


## Update

LoRa includes a separate updater tool named `lora-upgrader.py` which downloads from hardcoded repositories different
file types (txt, pdf, csv, yara, xlx, xlsx, ioc) and extracts from them with the help of
[ioc_parser](https://github.com/armbues/ioc_parser) the indicators we are interested in such as MD5s, SHA256s, URLs, Filenames,
Hosts and then proceeds to build the corresponding yara rules. The updater can be called through the server with the  --update
flag.

```
usage: lora-upgrader.py [-h] [-l log-file] [--nolog] [--debug]

optional arguments:
  -h, --help   show this help message and exit
  -l log-file  Log file
  --nolog      Don't write a local log file
  --debug      Debug output
```

## Dependencies

See the dependencies of the two tools.

cherrypy(server)

openpyxl

lxml



## Client

We can give to the client arguments for the operation we want it to do.
For example we can tell it to use the rules we want to check separated by comma
or just write 'all' for all the available rules we have. We can also do a one time check
or make it run scans with time intervals.

The available checks are {mem-scan, disk-scan, mem-dump, prefetch, triage, web-hist}

mem-scan: scan the memory

disk-scan: scan the disk from a path and down(excludes taken into consideration)

mem-dump: dumps the current memory to a image file for further investigation

prefetch:

  Info:

  Each time you turn on your computer, Windows keeps track of the way your computer starts and which programs you commonly open.
  Windows saves this information as a number of small files in the prefetch folder.
  The next time you turn on your computer, Windows refers to these files to help speed the start process.

With this we can identify the processes that start with booting our system and see if there is anything
malicious. The output format is csv and the results are located in \LoRa\win32\w1000\data\prefetch-{name of client pc}\{folder with latest time stamp}

triage: Collects triage information from the endpoint by checking Sysinternal / third-party / BATCH files
Checks if Mcafee epo agent is installed and if not an exception is raised which is normal.


web-hist: Collects the web history from various internet browsers and outputs it in a different csv file for each user.
Currently tested only for microsoft edge 10. The output has the columns below.
URL,Title,Visit Time,Visit Count,Visited From,Visit Type,Web Browser,User Profile,Browser Profile,URL Length,Typed Count


## Server

The server is responsible for updating the signature base, delivering the rules asked by the client and
returing in a dictionary form ioc data such as filenames, ips, hosts, hashes. The server running is cherrypy
and it offers parallelism of requests.


# Loki vs Rastrea2r

The two tools had some code blocks with the same functionality. In order to merge them in one tool I had to
choose which specific parts of both are going to survive to the final product. Through comparison and checking
I concluded to the following:

disk-scan:

rastrea2r only does rule match - loki filename and hash check

mem-scan:

loki checks processes connections

loki checks Sysforensics

loki does not check if working size bigger than a default due to performance


# Problems

The only problem encountered is with some protected pdf files which the pdfminer could not open to parse.
Solution: The one responsible for the server must transform the problematic pdf files to .xps and back to .pdf.
That way the protection is removed and we can parse the documents. There is only one corrupted file within all the
repositories from which we build our signature-base.

# Added features

Searching and parsing iocs from the site threatexpert. Scanning the registries for indicators that malware creates as well
as mutexes.
