rule Secrets_of_the_Comfoo_Masters
{
	strings:
		$MD51 = "2b29f0224b632fdd00d0a30527b795b7"
		$Filename1 = "rlycfg.dll"
		$Filepath1 = "C:\\WINDOWS\\system32\\tabcteng.dll"
		$Filename2 = "netman.dll"
		$Filename3 = "tabcteng.dll"
		$Filename4 = "rasauto.dll"
		$Filename5 = "sens.dll"
		$Filename6 = "cmmos.dll"
		$Filename7 = "jacpet.dll"
		$Filename8 = "javadb.dll"
		$Filename9 = "mszlobm.dll"
		$Filename10 = "netfram.dll"
		$Filename11 = "ntdapie.dll"
		$Filename12 = "ntdelu.dll"
		$Filename13 = "ntobm.dll"
		$Filename14 = "odbm.dll"
		$Filename15 = "senss.dll"
		$Filename16 = "suddec.dll"
		$Filename17 = "vmmreg32.dll"
		$Filename18 = "wininete.dll"
	condition:
		$MD51 or $Filename1 or $Filepath1 or $Filename2 or $Filename3 or $Filename4 or $Filename5 or $Filename6 or $Filename7 or $Filename8 or $Filename9 or $Filename10 or $Filename11 or $Filename12 or $Filename13 or $Filename14 or $Filename15 or $Filename16 or $Filename17 or $Filename18
}