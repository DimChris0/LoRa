rule China_Peace_Palace
{
	strings:
		$CVE1 = "CVE-2015-5119"
		$Host1 = "www.pca-cpa.org"
		$Filename1 = "movie.swf"
		$Host2 = "pic.nicklockluckydog.org"
		$Filename2 = "Rdws.exe"
		$MD51 = "B4522D05A9E3A034AF481A7797A445EA"
		$Filename3 = "LMS.exe"
		$Filename4 = "dbghelp.dll"
		$Host3 = "ssl.nicklockluckydog.org"
		$Host4 = "books.blueworldlink2015.net"
		$Host5 = "vpn.nicklockluckydog.org"
		$Host6 = "blueworldlink2015.net"
		$Host7 = "aol.com"
		$Host8 = "nicklockluckydog.org"
		$MD52 = "DFDC5B09C4DEA79EB7F5B9E4E76EECF9"
		$MD53 = "2EE25DE7BD6A2705F3F8DDE0DD681E96"
		$MD54 = "16E5A27BD55E0B4E595C9743F4C75611"
		$MD55 = "5877D15215B7F398319F0DE7BA7B1947"
	condition:
		$CVE1 or $Host1 or $Filename1 or $Host2 or $Filename2 or $MD51 or $Filename3 or $Filename4 or $Host3 or $Host4 or $Host5 or $Host6 or $Host7 or $Host8 or $MD52 or $MD53 or $MD54 or $MD55
}