rule Presentation_Targeted_Attacks_EN
{
	strings:
		$Filename1 = "jminet7.sys"
		$Filename2 = "cmi4432.sys"
		$Filename3 = "res302.dll"
		$Filename4 = "res302.dll"
		$Filename5 = "lsass.exe"
		$Filename6 = "lsass.exe"
		$Filename7 = "svchost.exe"
		$Filename8 = "services.exe"
		$Filename9 = "lsass.exe"
		$Filename10 = "alg.exe"
		$Filename11 = "imapi.exe"
		$Filename12 = "spoolsv.exe"
		$Filename13 = "svchost.exe"
	condition:
		$Filename1 or $Filename2 or $Filename3 or $Filename4 or $Filename5 or $Filename6 or $Filename7 or $Filename8 or $Filename9 or $Filename10 or $Filename11 or $Filename12 or $Filename13
}