rule th3bug_Watering_Hole_PoisonIvy
{
	strings:
		$IP1 = "115.23.172.151"
		$IP2 = "203.69.42.22"
		$Filename1 = "diff.exe"
		$Filename2 = "gmuweb.exe"
		$Filename3 = "PYvBte.jar"
		$Host1 = "www.npec.com"
		$Host2 = "diff.qohub.info"
		$Host3 = "www.aanon.com"
		$Host4 = "diff.exewww.npec.com"
		$Host5 = "uyghurweb.net"
		$SHA2561 = "ba509a1d752f3165dc2821e0b1c6543c15988fd7abd4e56c6155de09d1640ce9"
		$SHA2562 = "9d149baceaaff2a67161fec9b8978abc22f0a73a1c8ce87edf6e2fb673ac7374"
		$MD51 = "18ad696f3459bf47f97734f2f14506e3"
		$MD52 = "1ea41812a0114e5c6ae76330e7b4af69"
		$IP3 = "203.69.42.23"
		$Filename4 = "setup.exe"
		$Host6 = "www.ep66.com"
		$SHA2563 = "ccfe61a28f35161c19340541dfd839075e31cd3b661f0936a4c667d805a65136"
		$SHA2564 = "7f39e5b9d46386dd8142ef40ae526343274bdd5f27e38c07b457d290a277e807"
		$MD53 = "7b0cb4d14d3d8b6ccc7453f7ddb33997"
		$MD54 = "efad656db0f9cc92b1e15dc9c540e407"
		$Filename5 = "AppletLow.jar"
		$Host7 = "app.qohub.info"
		$SHA2565 = "e3d02e5f69d3c2092657d64c39aa0aea2a16ce804a47f3b5cf44774cde3166fe"
		$MD55 = "0cabd6aec2555e64bdf39320f338e027"
	condition:
		$IP1 or $IP2 or $Filename1 or $Filename2 or $Filename3 or $Host1 or $Host2 or $Host3 or $Host4 or $Host5 or $SHA2561 or $SHA2562 or $MD51 or $MD52 or $IP3 or $Filename4 or $Host6 or $SHA2563 or $SHA2564 or $MD53 or $MD54 or $Filename5 or $Host7 or $SHA2565 or $MD55
}