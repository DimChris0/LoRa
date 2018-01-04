rule in_depth_analysis_of_hydraq_final_231538
{
	strings:
		$CVE1 = "CVE-2010-0249"
		$CVE2 = "CVE-2010-0249"
		$Filename1 = "calc.exe"
		$Filename2 = "a.exe"
		$Host1 = "ftpaccess.cc"
		$Filename3 = "a.exe"
		$Filename4 = "b.exe"
		$Filename5 = "a.exe"
		$Filename6 = "Rasmon.dll"
		$Filename7 = "Svchost.exe"
		$Filename8 = "svchost.exe"
		$Registry1 = "HKLM\\SOFTWARE\\Microsoft\\Windows"
		$Registry2 = "HKLM\\SOFTWARE\\Microsoft\\Windows"
		$Filename9 = "DFS.bat"
		$Filename10 = "b.exe"
		$Filename11 = "Svchost.exe"
		$Filename12 = "svchost.exe"
		$Filename13 = "Rasmon.dll"
		$Registry3 = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\RaS"
		$Registry4 = "HKLM\\SOFTWARE\\Microsoft\\WindowsNT\\CurrentVersions\\Svchost\\netsvcs"
		$Filename14 = "Svchost.exe"
		$Registry5 = "HKLM\\Software\\Sun\\1"
		$IP1 = "111.222.123.111"
		$IP2 = "168.95.1.1"
		$Registry6 = "HKLM\\Software\\Sun\\1"
		$Registry7 = "HKLM\\Software\\Sun\\1"
		$Filename15 = "acelpvc.dll"
		$Filename16 = "VedioDriver.dll"
		$Filename17 = "mdm.exe"
		$Registry8 = "HKLM\\Software\\Sun\\IsoTp"
		$Registry9 = "HKLM\\Software"
		$Registry10 = "HKLM\\Software\\Sun"
		$Filename18 = "acelpvc.dll"
		$Filename19 = "VedioDriver.dll"
		$Filename20 = "acelpvc.dll"
		$Filename21 = "VedioDriver.dll"
		$Filename22 = "mdm.exe"
		$URL1 = "http://www.cert.org/tech_tips/securing_browser"
		$URL2 = "http://www.microsoft.com/protect/yourself/password/create.mspx"
		$Host2 = "www.cert.org"
		$URL3 = "http://community.ca.com/blogs/securityadvisor/archive/2009/02/24/attackers-love-zero-day.asp"
		$Host3 = "community.ca.com"
		$Host4 = "ca.com"
		$Email1 = "virus@ca.com"
		$Filepath1 = "C:\\Documents"
		$Filename23 = "svchost.exe"
		$Filename24 = "kernel32.dll"
		$Registry11 = "HKLM\\SYSTEM\\CurrentControlSet\\Services"
		$Registry12 = "HKLM\\SYSTEM\\CurrentControlSet\\Services"
		$Filepath2 = "C:\\Documents"
		$Filename25 = "svchost.exe"
		$Filename26 = "svchost.exe"
		$Filename27 = "rundll32.exe"
		$Filename28 = "rundll32.exe"
		$Filename29 = "cmd.exe"
		$Filename30 = "cmd.exe"
		$Registry13 = "HKLM\\SYSTEM\\CurrentControlSet\\Services"
		$Registry14 = "HKLM\\SYSTEM\\CurrentControlSet\\Services"
		$Registry15 = "HKLM\\SYSTEM\\CurrentControlSet\\Services"
		$Registry16 = "HKLM\\SYSTEM\\CurrentControlSet\\Services"
		$Registry17 = "HKLM\\SYSTEM\\CurrentControlSet\\Services"
		$Registry18 = "HKLM\\SYSTEM\\CurrentControlSet\\Services"
		$Registry19 = "HKLM\\SYSTEM\\CurrentControlSet\\Services"
		$Registry20 = "HKLM\\SYSTEM\\CurrentControlSet\\Services"
		$Registry21 = "HKLM\\SYSTEM\\CurrentControlSet\\Services"
		$Registry22 = "HKLM\\SOFTWARE\\Microsoft\\Windows"
		$Registry23 = "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
		$Filename31 = "acelpvc.dll"
		$Filename32 = "acelpvc.dll"
		$Filename33 = "acelpvc.dll"
		$Filename34 = "VedioDriver.dll"
		$Filename35 = "VedioDriver.dll"
		$Filename36 = "acelpvc.dll"
		$Filename37 = "acelpvc.dll"
		$Filename38 = "VedioDriver.dll"
		$Filename39 = "VedioDriver.dll"
		$Filename40 = "VedioDriver.dll"
		$Filename41 = "user32.dll"
		$Filename42 = "Acelpvc.dll"
		$URL4 = "http://www.security.nl/files/aurorafiles.txt"
		$IP3 = "69.164.192.4"
		$Filename43 = "VedioDriver.dll"
		$Host5 = "360.homeunix.com"
		$Host6 = "www.ccmp1.com"
		$Host7 = "blog1.servebeer.com"
		$Host8 = "sl1.homelinux.org"
		$Host9 = "update.ourhobby.com"
		$Host10 = "ftp2.homeunix.com"
		$Host11 = "www.security.nl"
		$Host12 = "alt1.homelinux.com"
		$Host13 = "amt1.homelinux.com"
		$Host14 = "aop1.homelinux.com"
		$Host15 = "app1.homelinux.com"
		$Host16 = "blogspot.blogsite.org"
		$Host17 = "filoups.info"
		$Host18 = "ftpaccess.cc"
		$Host19 = "google.homeunix.com"
		$Host20 = "members.linode.com"
		$Host21 = "tyuqwer.dyndns.org"
		$Host22 = "voanews.ath.cx"
		$Host23 = "webswan.33iqst.com"
		$Host24 = "yahoo.8866.org"
		$Host25 = "ymail.ath.cx"
		$Host26 = "yahooo.8866.org"
		$Host27 = "connectproxy.3322.org"
		$Host28 = "csport.2288.org"
		$URL5 = "http://googleblog.blogspot.com/2010/01/new-approach-to-china.html"
		$URL6 = "http://www.state.gov/secretary/rm/2010/01/135519.htm"
		$URL7 = "http://www.dni.gov/testimonies/20100202_testimony.pdf"
		$URL8 = "http://www.scribd.com/doc/13731776/Tracking-GhostNet-Investigating-a-Cyber-Espionage-Network"
		$URL9 = "http://oreilly.com/catalog/9780596802165"
		$URL10 = "http://www.forensicfocus.com/downloads/windows-registry-quick-reference.pdf"
		$Filename44 = "new-approach-to-china.html"
		$Filename45 = "135519.htm"
		$Filename46 = "20100202_testimony.pdf"
		$Filename47 = "windows-registry-quick-reference.pdf"
		$Host29 = "googleblog.blogspot.com"
		$Host30 = "www.state.gov"
		$Host31 = "www.dni.gov"
		$Host32 = "www.scribd.com"
		$Host33 = "oreilly.com"
		$Host34 = "www.forensicfocus.com"
		$CVE3 = "CVE-2010-0249"
	condition:
		$CVE1 or $CVE2 or $Filename1 or $Filename2 or $Host1 or $Filename3 or $Filename4 or $Filename5 or $Filename6 or $Filename7 or $Filename8 or $Registry1 or $Registry2 or $Filename9 or $Filename10 or $Filename11 or $Filename12 or $Filename13 or $Registry3 or $Registry4 or $Filename14 or $Registry5 or $IP1 or $IP2 or $Registry6 or $Registry7 or $Filename15 or $Filename16 or $Filename17 or $Registry8 or $Registry9 or $Registry10 or $Filename18 or $Filename19 or $Filename20 or $Filename21 or $Filename22 or $URL1 or $URL2 or $Host2 or $URL3 or $Host3 or $Host4 or $Email1 or $Filepath1 or $Filename23 or $Filename24 or $Registry11 or $Registry12 or $Filepath2 or $Filename25 or $Filename26 or $Filename27 or $Filename28 or $Filename29 or $Filename30 or $Registry13 or $Registry14 or $Registry15 or $Registry16 or $Registry17 or $Registry18 or $Registry19 or $Registry20 or $Registry21 or $Registry22 or $Registry23 or $Filename31 or $Filename32 or $Filename33 or $Filename34 or $Filename35 or $Filename36 or $Filename37 or $Filename38 or $Filename39 or $Filename40 or $Filename41 or $Filename42 or $URL4 or $IP3 or $Filename43 or $Host5 or $Host6 or $Host7 or $Host8 or $Host9 or $Host10 or $Host11 or $Host12 or $Host13 or $Host14 or $Host15 or $Host16 or $Host17 or $Host18 or $Host19 or $Host20 or $Host21 or $Host22 or $Host23 or $Host24 or $Host25 or $Host26 or $Host27 or $Host28 or $URL5 or $URL6 or $URL7 or $URL8 or $URL9 or $URL10 or $Filename44 or $Filename45 or $Filename46 or $Filename47 or $Host29 or $Host30 or $Host31 or $Host32 or $Host33 or $Host34 or $CVE3
}