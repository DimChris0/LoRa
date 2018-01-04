rule Inside_Report_by_Infosec_Consortium
{
	strings:
		$Host1 = "www.researchbundle.com"
		$Host2 = "www.researchbundle.com"
		$Host3 = "www.researchbundle.com"
		$Host4 = "www.researchbundle.com"
		$Host5 = "www.researchbundle.com"
		$Host6 = "www.researchbundle.com"
		$Host7 = "www.researchbundle.com"
		$Host8 = "www.researchbundle.com"
		$Host9 = "www.researchbundle.com"
		$Host10 = "www.researchbundle.com"
		$Host11 = "gov.in"
		$Host12 = "www.zone-h.org"
		$Host13 = "www.researchbundle.com"
		$Host14 = "www.researchbundle.com"
		$Filename1 = "2013.doc"
		$Filename2 = "act.doc"
		$Filename3 = "Boom.doc"
		$Filename4 = "3.doc"
		$Filename5 = "split.doc"
		$Host15 = "www.researchbundle.com"
		$CVE1 = "CVE-2012-0158"
		$CVE2 = "CVE-2010-3333"
		$SHA11 = "25ac3098261df8aa09449a9a4c445c91321352af"
		$Filename6 = "travnet_A.exe"
		$Host16 = "www.researchbundle.com"
		$SHA2561 = "a75fdd9e52643dc7a1790c79cbfffe9348f80a9b0984eafd90723bf7ca68f4ce"
		$MD51 = "d286c4cdf40e2dae5362eff562bccd3a"
		$Host17 = "www.researchbundle.com"
		$Filename7 = "temp.bat"
		$Filename8 = "6to4ex.dll"
		$Filename9 = "temp.bat"
		$Host18 = "www.researchbundle.com"
		$SHA12 = "b80d436afcf2f0493f2317ff1a38c9ba329f24b1"
		$URL1 = "http://www.newesyahoo.com/traveler1/net/nettraveler.asp"
		$Filename10 = "6to4ex.dll"
		$Filename11 = "6to4ex.dll"
		$Filename12 = "6to4ex.dll"
		$Host19 = "www.researchbundle.com"
		$SHA2562 = "ed6ad64dad85fe11f3cc786c8de1f5b239115b94e30420860f02e820ffc53924"
		$MD52 = "452660884ebe3e88ddabe2b340113c8a"
		$Host20 = "www.researchbundle.com"
		$Host21 = "www.researchbundle.com"
		$Filename13 = "system_t.dll"
		$Filename14 = "system_t.dll"
		$Host22 = "www.researchbundle.com"
		$Host23 = "www.researchbundle.com"
		$Filename15 = "d.dll"
		$Filename16 = "system_t.dll"
		$Host24 = "www.researchbundle.com"
		$Host25 = "www.researchbundle.com"
		$URL2 = "http://www.newesyahoo.com/traveler1/net/nettraveler.asp?hostid=00CD1A40&hostname=ComputerName&ho"
		$Host26 = "www.researchbundle.com"
		$Host27 = "www.researchbundle.com"
		$SHA13 = "dc63b4b9ee2f8486b96ce62be4a31e041d422ef7"
		$URL3 = "http://www.viprambler.com/newsinfo/uld/nettraveler.asp"
		$Filename17 = "travnet_B.exe"
		$Host28 = "www.viprambler.com"
		$Host29 = "www.researchbundle.com"
		$SHA2563 = "e547e8a8bc27d65dca92bc861be82e1c94b9c9aca8a2b75381e9b16e4ad89600"
		$MD53 = "9d22897b05261ad66645887b094a43c7"
		$Filename18 = "csmss.exe"
		$Host30 = "www.researchbundle.com"
		$Host31 = "www.researchbundle.com"
		$Filename19 = "Process.dll"
		$Host32 = "www.researchbundle.com"
		$URL4 = "http://www.viprambler.com/newsinfo/uld/nettraveler.asp"
		$Host33 = "www.viprambler.com"
		$Host34 = "www.pkspring.net"
		$Host35 = "www.viprambler.com"
		$Host36 = "www.researchbundle.com"
		$Host37 = "www.viprambler.com"
		$Host38 = "www.researchbundle.com"
		$Host39 = "www.researchbundle.com"
		$Host40 = "pkspring.net"
		$Host41 = "www.researchbundle.com"
		$Host42 = "www.researchbundle.com"
		$Host43 = "www.researchbundle.com"
		$Host44 = "www.researchbundle.com"
		$URL5 = "http://mail.sina.com.cn"
		$Host45 = "sina.com"
		$Host46 = "mail.sina.com.cn"
		$Host47 = "www.researchbundle.com"
		$Email1 = "livep92@hotmail.com"
		$Email2 = "chenjm@sina.com"
		$Host48 = "discoverypeace.org"
		$Host49 = "discoverypeace.org"
		$Host50 = "www.researchbundle.com"
		$Email3 = "livep92@hotmail.com"
		$Host51 = "pkstring.net"
		$Host52 = "www.researchbundle.com"
		$Host53 = "www.researchbundle.com"
		$Host54 = "www.researchbundle.com"
		$Host55 = "gov.in"
		$Host56 = "karnataka.gov.in"
		$Host57 = "www.researchbundle.com"
		$Host58 = "www.researchbundle.com"
		$Host59 = "www.researchbundle.com"
		$Host60 = "www.researchbundle.com"
		$Host61 = "www.researchbundle.com"
		$URL6 = "http://www.deccanchronicle.com/130608/news-current-affairs/article/india-loses-22gb-data-cyber-attack"
		$URL7 = "http://newindianexpress.com/nation/Cyber-defences-are-not-robust-enough/2013/06/16/article1636933.ece"
		$IP1 = "182.50.130.68"
		$Filename20 = "kaspersky-the-net-traveler-part1-final.pdf"
		$Host62 = "www.deccanchronicle.com"
		$Host63 = "newindianexpress.com"
		$Host64 = "www.researchbundle.com"
		$MD54 = "0f23c9e6c8ec38f62616d39de5b00ffb"
	condition:
		$Host1 or $Host2 or $Host3 or $Host4 or $Host5 or $Host6 or $Host7 or $Host8 or $Host9 or $Host10 or $Host11 or $Host12 or $Host13 or $Host14 or $Filename1 or $Filename2 or $Filename3 or $Filename4 or $Filename5 or $Host15 or $CVE1 or $CVE2 or $SHA11 or $Filename6 or $Host16 or $SHA2561 or $MD51 or $Host17 or $Filename7 or $Filename8 or $Filename9 or $Host18 or $SHA12 or $URL1 or $Filename10 or $Filename11 or $Filename12 or $Host19 or $SHA2562 or $MD52 or $Host20 or $Host21 or $Filename13 or $Filename14 or $Host22 or $Host23 or $Filename15 or $Filename16 or $Host24 or $Host25 or $URL2 or $Host26 or $Host27 or $SHA13 or $URL3 or $Filename17 or $Host28 or $Host29 or $SHA2563 or $MD53 or $Filename18 or $Host30 or $Host31 or $Filename19 or $Host32 or $URL4 or $Host33 or $Host34 or $Host35 or $Host36 or $Host37 or $Host38 or $Host39 or $Host40 or $Host41 or $Host42 or $Host43 or $Host44 or $URL5 or $Host45 or $Host46 or $Host47 or $Email1 or $Email2 or $Host48 or $Host49 or $Host50 or $Email3 or $Host51 or $Host52 or $Host53 or $Host54 or $Host55 or $Host56 or $Host57 or $Host58 or $Host59 or $Host60 or $Host61 or $URL6 or $URL7 or $IP1 or $Filename20 or $Host62 or $Host63 or $Host64 or $MD54
}