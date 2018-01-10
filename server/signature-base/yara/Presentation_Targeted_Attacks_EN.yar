rule Presentation_Targeted_Attacks_EN
{
	strings:
		$Filename1 = "jminet7.sys"
		$Filename2 = "cmi4432.sys"
		$Filename3 = "res302.dll"
		$Filename4 = "lsass.exe"
		$Filename5 = "svchost.exe"
		$Filename6 = "services.exe"
		$Filename7 = "alg.exe"
		$Filename8 = "imapi.exe"
		$Filename9 = "spoolsv.exe"
	condition:
		$Filename1 or $Filename2 or $Filename3 or $Filename4 or $Filename5 or $Filename6 or $Filename7 or $Filename8 or $Filename9
}