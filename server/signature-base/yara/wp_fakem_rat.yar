rule wp_fakem_rat
{
	strings:
		$URL1 = "https://media.blackhat.com/bh-eu-10/presentations/Dereszowski/BlackHat-EU-2010"
		$Filename1 = "ThemanyfacesofGh0stRat.pdf"
		$Filename2 = "wp-know-your-digital-enemy.pdf"
		$Filename3 = "Dereszowski-Targeted-Attacks-slides.pdf"
		$Filename4 = "detecting-apt-activity-with-network-traffic-analysis.pdf"
		$Host1 = "media.blackhat.com"
		$CVE1 = "CVE-2010-3333"
		$CVE2 = "CVE-2012-0158"
		$CVE3 = "CVE-2009-3129"
		$URL2 = "http://upx.sourceforge.net"
		$URL3 = "https://twitter.com/mikko/status/232851667446538241"
		$URL4 = "https://www.mysonicwall.com"
		$URL5 = "https://twitter.com/diocyde"
		$Filename5 = "hkcmd.exe"
		$Filename6 = "tpframe.exe"
		$Host2 = "upx.sourceforge.net"
		$Host3 = "www.mysonicwall.com"
		$Host4 = "vcvcvcvc.dyndns.org"
		$Host5 = "zjhao.dtdns.net"
		$Host6 = "avira.suroot.com"
		$Host7 = "apple12.crabdance.com"
		$Host8 = "apple12.co.cc"
		$Host9 = "yourturbe.org"
		$Host10 = "endless.zapto.org"
		$Host11 = "sytes.net"
	condition:
		$URL1 or $Filename1 or $Filename2 or $Filename3 or $Filename4 or $Host1 or $CVE1 or $CVE2 or $CVE3 or $URL2 or $URL3 or $URL4 or $URL5 or $Filename5 or $Filename6 or $Host2 or $Host3 or $Host4 or $Host5 or $Host6 or $Host7 or $Host8 or $Host9 or $Host10 or $Host11
}