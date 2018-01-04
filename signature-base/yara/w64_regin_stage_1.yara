rule w64_regin_stage_1
{
	strings:
		$SHA11 = "5191d7e28ffd1bc76ec7ed02d861679a77f2c239"
		$Filename1 = "wshtcpip.dll"
		$Filename2 = "wshnetc.dll"
		$Filename3 = "wshtcpip.dll"
		$Filename4 = "wshtcpip.dll"
		$Filename5 = "wshnetc.dll"
		$Filename6 = "wshnetc.dll"
		$Filename7 = "wshnetc.dll"
		$Filename8 = "wshnetc.dll"
		$Filename9 = "wshnetc.dll"
		$Filename10 = "wshnetc.dll"
		$Filename11 = "wshnetc.dll"
		$Filename12 = "wshnetc.dll"
		$Filename13 = "wshnetc.dll"
		$Filename14 = "wshnetc.dll"
		$Filename15 = "wshnetc.dll"
		$Filename16 = "wshnetc.dll"
		$Filename17 = "wshnetc.dll"
		$Filename18 = "wshnetc.dll"
		$Filename19 = "wshnetc.dll"
		$Filename20 = "wshnetc.dll"
	condition:
		$SHA11 or $Filename1 or $Filename2 or $Filename3 or $Filename4 or $Filename5 or $Filename6 or $Filename7 or $Filename8 or $Filename9 or $Filename10 or $Filename11 or $Filename12 or $Filename13 or $Filename14 or $Filename15 or $Filename16 or $Filename17 or $Filename18 or $Filename19 or $Filename20
}