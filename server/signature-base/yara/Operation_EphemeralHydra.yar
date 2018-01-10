rule Operation_EphemeralHydra
{
	strings:
		$Filename1 = "rundll32.exe"
		$IP1 = "111.68.9.93"
		$Host1 = "ieee.boeing-job.com"
		$IP2 = "58.64.143.244"
		$IP3 = "58.64.213.104"
		$Host2 = "ad04.bounceme.net"
		$Host3 = "dll.freshdns.org"
		$Host4 = "grado.selfip.com"
		$Host5 = "usc-data.suroot.com"
		$Host6 = "usa-mail.scieron.com"
		$CVE1 = "CVE-2013-3893"
		$MD51 = "104130d666ab3f640255140007f0b12d"
		$MD52 = "90a37e54c53ffb78969644b1a7038e8c"
		$MD53 = "acbc249061a6a2fb09271a68d53567d9"
		$MD54 = "20854f54b0d03118681410245be39bd8"
		$Filename2 = "McpRoXy.exe"
		$Filename3 = "SoundMax.dll"
	condition:
		$Filename1 or $IP1 or $Host1 or $IP2 or $IP3 or $Host2 or $Host3 or $Host4 or $Host5 or $Host6 or $CVE1 or $MD51 or $MD52 or $MD53 or $MD54 or $Filename2 or $Filename3
}