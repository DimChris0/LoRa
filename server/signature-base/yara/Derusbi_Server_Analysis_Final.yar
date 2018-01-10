rule Derusbi_Server_Analysis_Final
{
	strings:
		$Filename1 = "svchost.exe"
		$Filename2 = "ZhuDongFangYu.exe"
		$Registry1 = "HKLM\\SOFTWARE\\Microsoft\\Rpc\\Security"
	condition:
		$Filename1 or $Filename2 or $Registry1
}rule Derusbi_Server_Analysis_Final
{
	strings:
		$Filename1 = "svchost.exe"
		$Filename2 = "ZhuDongFangYu.exe"
		$Registry1 = "HKLM\\SOFTWARE\\Microsoft\\Rpc\\Security"
	condition:
		$Filename1 or $Filename2 or $Registry1
}