rule regin_analysis
{
	strings:
		$Filename1 = "usbclass.sys"
		$Filename2 = "adpu160.sys"
		$Filename3 = "services.exe"
		$Filename4 = "services.exe"
		$Filename5 = "prefs.js"
		$Filename6 = "refs.js"
		$Filename7 = "svcsstat.exe"
		$Filename8 = "wshnetc.dll"
		$Filename9 = "usbclass.sys"
		$Filename10 = "adpu160.sys"
		$Filename11 = "winhttpc.dll"
		$Filename12 = "wshnetc.dll"
		$Filename13 = "wshnetc.dll"
		$Filename14 = "svcstat.exe"
		$MD51 = "2c8b9d2885543d7ade3cae98225e263b"
		$MD52 = "4b6b86c7fec1c574706cecedf44abded"
		$MD53 = "187044596bc1328efa0ed636d8aa4a5c"
		$MD54 = "06665b96e293b23acc80451abb413e50"
		$MD55 = "d240f06e98c8d3e647cbf4d442d79475"
		$MD56 = "6662c390b2bbbd291ec7987388fc75d7"
		$MD57 = "ffb0b9b5b610191051a7bdf0806e1e47"
		$MD58 = "b29ca4f22ae7b7b25f79c1d4a421139d"
		$MD59 = "1c024e599ac055312a4ab75b3950040a"
		$MD510 = "ba7bb65634ce1e30c1e5415be3d1db1d"
		$MD511 = "b505d65721bb2453d5039a389113b566"
		$MD512 = "b269894f434657db2b15949641a67532"
		$MD513 = "bfbe8c3ee78750c3a520480700e440f8"
		$Filename15 = "svcsstat.exe"
	condition:
		$Filename1 or $Filename2 or $Filename3 or $Filename4 or $Filename5 or $Filename6 or $Filename7 or $Filename8 or $Filename9 or $Filename10 or $Filename11 or $Filename12 or $Filename13 or $Filename14 or $MD51 or $MD52 or $MD53 or $MD54 or $MD55 or $MD56 or $MD57 or $MD58 or $MD59 or $MD510 or $MD511 or $MD512 or $MD513 or $Filename15
}