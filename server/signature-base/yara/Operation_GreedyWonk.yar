rule Operation_GreedyWonk
{
	strings:
		$IP1 = "12.0.0.4"
		$IP2 = "11.7.700.261"
		$Host1 = "www.piie.com"
		$Host2 = "www.arce.org"
		$Host3 = "www.srf.org"
		$Filename1 = "MSVCR71.dll"
		$Filename2 = "HXDS.dll"
		$IP3 = "74.126.177.68"
		$IP4 = "103.246.246.103"
		$IP5 = "192.74.246.219"
		$Host4 = "java.ns1.name"
		$Host5 = "adservice.no-ip.org"
		$Host6 = "wmi.ns01.us"
		$Host7 = "proxy.ddns.info"
		$MD51 = "507aed81e3106da8c50efb3a045c5e2b"
		$IP6 = "204.200.222.136"
		$IP7 = "74.126.177.70"
		$IP8 = "74.126.177.241"
		$IP9 = "159.54.62.92"
		$IP10 = "76.73.80.188"
		$Filename3 = "BrightBalls.swf"
		$Host8 = "updatedns.ns02.us"
		$Host9 = "updatedns.ns01.us"
		$Host10 = "fuckchina.govnb.com"
		$Host11 = "microsafes.no-ip.org"
		$Host12 = "www.cdi.org"
		$Host13 = "windows.ddns.us"
		$CVE1 = "CVE-2012-0779"
		$MD52 = "7995a9a6a889b914e208eb924e459ebc"
		$MD53 = "bf60b8d26bc0c94dda2e3471de6ec977"
		$MD54 = "fd69793bd63c44bbb22f9c4d46873252"
		$MD55 = "88b375e3b5c50a3e6c881bc96c926928"
		$MD56 = "cd07a9e49b1f909e1bd9e39a7a6e56b4"
		$MD57 = "8936c87a08ffa56d19fdb87588e35952"
		$MD58 = "1ec5141051776ec9092db92050192758"
		$IP11 = "194.183.224.75"
		$Filename4 = "test.jar"
		$Host14 = "ids.ns01.us"
		$Host15 = "www.ceps.be"
		$Host16 = "shop.fujifilm.be"
		$CVE2 = "CVE-2012-0507"
		$MD59 = "7d810e3564c4eb95bcb3d11ce191208e"
		$MD510 = "52aa791a524b61b129344f10b4712f52"
	condition:
		$IP1 or $IP2 or $Host1 or $Host2 or $Host3 or $Filename1 or $Filename2 or $IP3 or $IP4 or $IP5 or $Host4 or $Host5 or $Host6 or $Host7 or $MD51 or $IP6 or $IP7 or $IP8 or $IP9 or $IP10 or $Filename3 or $Host8 or $Host9 or $Host10 or $Host11 or $Host12 or $Host13 or $CVE1 or $MD52 or $MD53 or $MD54 or $MD55 or $MD56 or $MD57 or $MD58 or $IP11 or $Filename4 or $Host14 or $Host15 or $Host16 or $CVE2 or $MD59 or $MD510
}