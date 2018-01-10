rule EB_YetiJuly_Public
{
	strings:
		$CVE1 = "CVE-2011-0611"
		$IP1 = "1.0.14.706"
		$Filename1 = "sydmain.dll"
		$URL1 = "hxxp://www.ewon.biz/software/eCatcher/eCatcherSetup.exe"
		$Filename2 = "eCatcherSetup.exe"
		$Filename3 = "eCatcherSetup_v4.exe"
		$Host1 = "www.ewon.biz"
		$URL2 = "hxxp://www.mbconnectline.com/index.php/en"
		$Host2 = "www.mbconnectline.com"
		$Filename4 = "explore.dll"
		$Filename5 = "rundll32.exe"
		$IP2 = "91.203.6.71"
		$Host3 = "nahoonservices.com"
		$CVE2 = "CVE-2013-2465"
		$CVE3 = "CVE-2013-1347"
		$CVE4 = "CVE-2012-1723"
		$Host4 = "kinoporno.org"
		$Filename6 = "TMPprovider0XX.dll"
		$URL3 = "hxxp://securityxploded.com/browser-password-decryptor.php"
		$Host5 = "securityxploded.com"
		$Filename7 = "prx.jpg"
		$Filepath1 = "C:\\ProgramData\\Mail\\MailAg"
		$Filepath2 = "C:\\ProgramData\\Mail\\MailAg\\scs.jpg"
		$Filepath3 = "C:\\ProgramData\\Mail\\MailAg\\scs.txt"
		$Filepath4 = "C:\\ProgramData\\Mail\\MailAg\\fls.txt"
		$URL4 = "hxxp://www.ducklink.com"
		$Filename8 = "scs.jpg"
		$Host6 = "www.ducklink.com"
	condition:
		$CVE1 or $IP1 or $Filename1 or $URL1 or $Filename2 or $Filename3 or $Host1 or $URL2 or $Host2 or $Filename4 or $Filename5 or $IP2 or $Host3 or $CVE2 or $CVE3 or $CVE4 or $Host4 or $Filename6 or $URL3 or $Host5 or $Filename7 or $Filepath1 or $Filepath2 or $Filepath3 or $Filepath4 or $URL4 or $Filename8 or $Host6
}