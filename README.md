<br /># LoRa

Collecting & Hunting for Indicators of Compromise (IOC)
The two specialiced scanners [LOKI](https://github.com/Neo23x0/Loki) and [Rastrea2r](https://github.com/aboutsecurity/rastrea2r) 
have been merged into a new generic IOC scanner called LoRa. By using a client/server RESTful API, it can also hunt for IOCs 
on disk and memory across multiple systems using YARA rules. The server is the one responsible for finding, downloading the IOCs
and then serving them as yara rules to the clients. The clients recieve the data and proceeds to scan its system and produce the 
reports of the result.


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
Hosts and then proceeds to build the corresponding yara rules.

```
usage: lora-upgrader.py [-h] [-l log-file] [--nolog] [--debug]

optional arguments:
  -h, --help   show this help message and exit
  -l log-file  Log file
  --nolog      Don't write a local log file
  --debug      Debug output
```

## Dependencies

See the dependencies of the two tools.<br />
cherrypy(server)<br />
openpyxl<br />
lxml


