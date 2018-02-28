rule NetTraveler_Makeover_10th_Birthday
{
	strings:
		$Filename1 = "ashkarilanmaqta.doc"
		$CVE1 = "CVE-2012-0158"
		$MD51 = "b2385963d3afece16bd7478b4cf290ce"
		$Filename2 = "net.exe"
		$Filename3 = "Windowsupdataney.dll"
		$Filename4 = "svchost.exe"
		$MD52 = "c13c79ad874215cfec8d318468e3d116"
		$IP1 = "103.30.7.77"
		$IP2 = "216.83.32.29"
		$IP3 = "122.10.17.130"
		$IP4 = "103.1.42.1"
		$IP5 = "202.146.219.14"
		$IP6 = "103.17.117.201"
		$IP7 = "103.30.7.76"
		$Host1 = "uyghurinfo.com"
		$Host2 = "ssdcru.com"
		$Host3 = "uygurinfo.com"
		$Host4 = "samedone.com"
		$Host5 = "gobackto.net"
		$Host6 = "worksware.net"
		$Host7 = "jojomic.com"
		$Host8 = "angellost.net"
		$Host9 = "husden.com"
	condition:
		$Filename1 or $CVE1 or $MD51 or $Filename2 or $Filename3 or $Filename4 or $MD52 or $IP1 or $IP2 or $IP3 or $IP4 or $IP5 or $IP6 or $IP7 or $Host1 or $Host2 or $Host3 or $Host4 or $Host5 or $Host6 or $Host7 or $Host8 or $Host9
}