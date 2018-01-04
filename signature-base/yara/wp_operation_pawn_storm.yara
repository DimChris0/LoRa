rule wp_operation_pawn_storm
{
	strings:
		$CVE1 = "CVE-2010-3333"
		$Filename1 = "Attack_011012.doc"
		$CVE2 = "CVE-2012-0158"
		$CVE3 = "CVE-2012-0158"
		$Filename2 = "Part1.xls"
		$Filename3 = "Part2.xls"
		$Filename4 = "MH17.doc"
		$Filename5 = "Part1.xls"
		$Filename6 = "netids.dll"
		$Filename7 = "netidt.dll"
		$Filename8 = "coreshell.dll"
		$CVE4 = "CVE-2012-0158"
		$CVE5 = "CVE-2012-0158"
		$CVE6 = "CVE-2012-0158"
		$CVE7 = "CVE-2012-0158"
		$Filename9 = "dropper.exe"
		$Filename10 = "saver.scr"
		$Filename11 = "Part1.xls"
		$Filename12 = "saver.scr"
		$Filename13 = "MH17.doc"
		$CVE8 = "CVE-2010-3333"
		$CVE9 = "CVE-2012-0158"
		$CVE10 = "CVE-2012-0158"
		$Filename14 = "Dropper.exe"
		$Filename15 = "netids.dll"
		$Filename16 = "Saver.scr"
		$Filename17 = "Skype.exe"
		$Filename18 = "netids.dll"
		$Filename19 = "Part1.xls"
		$Filename20 = "Saver.scr"
		$Filename21 = "Install.exe"
		$Filename22 = "Coreshell.dll"
		$Filename23 = "coreshell.dll"
		$IP1 = "200.106.145.122"
		$Filename24 = "Netids.dll"
		$Filename25 = "Skype.exe"
		$Filename26 = "netids.dll"
		$Filename27 = "netids.dll"
		$Filename28 = "Netids.dll"
		$Filename29 = "Install.exe"
		$Filename30 = "netids.dll"
		$Filename31 = "Coreshell.dll"
		$IP2 = "70.85.221.20"
		$IP3 = "70.85.221.10"
		$IP4 = "70.85.221.10"
		$IP5 = "200.74.244.118"
		$Filename32 = "Netids.dll"
		$Filename33 = "Msmvs.exe"
		$Filename34 = "conhost.dll"
		$Filename35 = "Netids.dll"
		$Filename36 = "Netids.dll"
		$Filename37 = "Conhost.dll"
		$Filename38 = "advstoreshell.dll"
		$Filename39 = "Conhost.dll"
		$Filename40 = "netui.dll"
		$Filename41 = "Netui.dll"
		$Filename42 = "Advstoreshell.dll"
		$Host1 = "mail.hm.gov.hu"
		$IP6 = "46.166.162.90"
		$IP7 = "192.154.110.244"
		$URL1 = "http://nypost.com/2012/01/09/three"
		$URL2 = "http://malware.prevenity.com/2014/08"
		$URL3 = "http://thegoldenmessenger.blogspot"
		$Filename43 = "malware-info.html"
		$Filename44 = "malware_27.html"
		$Host2 = "nypost.com"
		$Host3 = "homelandsecurityme.com"
		$Host4 = "malware.prevenity.com"
		$Host5 = "www.eurosatory.com"
		$CVE11 = "CVE-2010-3333"
		$CVE12 = "CVE-2010-3333"
		$CVE13 = "CVE-2012-0158"
		$CVE14 = "CVE-2012-0158"
		$URL4 = "http://www.trendmicro.com"
	condition:
		$CVE1 or $Filename1 or $CVE2 or $CVE3 or $Filename2 or $Filename3 or $Filename4 or $Filename5 or $Filename6 or $Filename7 or $Filename8 or $CVE4 or $CVE5 or $CVE6 or $CVE7 or $Filename9 or $Filename10 or $Filename11 or $Filename12 or $Filename13 or $CVE8 or $CVE9 or $CVE10 or $Filename14 or $Filename15 or $Filename16 or $Filename17 or $Filename18 or $Filename19 or $Filename20 or $Filename21 or $Filename22 or $Filename23 or $IP1 or $Filename24 or $Filename25 or $Filename26 or $Filename27 or $Filename28 or $Filename29 or $Filename30 or $Filename31 or $IP2 or $IP3 or $IP4 or $IP5 or $Filename32 or $Filename33 or $Filename34 or $Filename35 or $Filename36 or $Filename37 or $Filename38 or $Filename39 or $Filename40 or $Filename41 or $Filename42 or $Host1 or $IP6 or $IP7 or $URL1 or $URL2 or $URL3 or $Filename43 or $Filename44 or $Host2 or $Host3 or $Host4 or $Host5 or $CVE11 or $CVE12 or $CVE13 or $CVE14 or $URL4
}