rule w64_regin_stage_1
{
	strings:
		$SHA11 = "5191d7e28ffd1bc76ec7ed02d861679a77f2c239"
		$Filename1 = "wshtcpip.dll"
		$Filename2 = "wshnetc.dll"
	condition:
		$SHA11 or $Filename1 or $Filename2
}