rule Operation_SnowMan
{
	strings:
		$Filename1 = "img.html"
		$Host1 = "vfw.org"
		$CVE1 = "CVE-2014-0322"
		$Filename2 = "stream.exe"
		$MD51 = "8455bbb9a210ce603a1b646b0d951bce"
		$IP1 = "118.99.60.142"
		$IP2 = "58.64.200.178"
		$IP3 = "58.64.200.179"
		$IP4 = "103.20.192.4"
		$IP5 = "58.64.199.22"
		$IP6 = "58.64.199.27"
		$IP7 = "58.64.199.25"
		$Host2 = "newss.effers.com"
		$Host3 = "info.flnet.org"
		$Host4 = "icybin.flnet.org"
		$Host5 = "book.flnet.org"
		$Host6 = "me.scieron.com"
		$Host7 = "dll.freshdns.org"
		$Host8 = "ali.blankchair.com"
		$Host9 = "cht.blankchair.com"
		$MD52 = "758886e58f9ea2ff22b57cbbb015166e"
		$MD53 = "0294f9280491f85d898ebe471f0fb58e"
		$MD54 = "9d20566a327076b7152bbf9ed20292c4"
		$Host10 = "rt.blankchair.com"
	condition:
		$Filename1 or $Host1 or $CVE1 or $Filename2 or $MD51 or $IP1 or $IP2 or $IP3 or $IP4 or $IP5 or $IP6 or $IP7 or $Host2 or $Host3 or $Host4 or $Host5 or $Host6 or $Host7 or $Host8 or $Host9 or $MD52 or $MD53 or $MD54 or $Host10
}