rule DEEP_PANDA_Sakula
{
	strings:
		$IP1 = "180.210.206.246"
		$Filename1 = "MediaSoft.exe"
		$Filename2 = "msi.dll"
		$MD51 = "d00b3169f45e74bb22a1cd684341b14a"
		$MD52 = "ae6f33f6cdc25dc4bda24b2bccff79fe"
		$MD53 = "0c2674c3a97c53082187d930efb645c2"
		$Host1 = "mster.com"
		$Email1 = "wendellom@yahoo.com"
		$IP2 = "198.200.45.112"
		$Host2 = "vpn.foundationssl.com"
		$Host3 = "foundationssl.com"
		$Host4 = "news.foundationssl.com"
		$Filename3 = "index.html"
	condition:
		$IP1 or $Filename1 or $Filename2 or $MD51 or $MD52 or $MD53 or $Host1 or $Email1 or $IP2 or $Host2 or $Host3 or $Host4 or $Filename3
}