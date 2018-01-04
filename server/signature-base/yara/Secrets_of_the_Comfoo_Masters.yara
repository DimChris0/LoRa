rule Secrets_of_the_Comfoo_Masters
{
	strings:
		$MD51 = "2b29f0224b632fdd00d0a30527b795b7"
		$Filename1 = "rlycfg.dll"
		$Filepath1 = "C:\\WINDOWS\\system32\\tabcteng.dll"
		$Filename2 = "netman.dll"
		$Filename3 = "tabcteng.dll"
		$Filename4 = "netman.dll"
		$Filename5 = "rasauto.dll"
		$Filename6 = "sens.dll"
		$Filename7 = "cmmos.dll"
		$Filename8 = "jacpet.dll"
		$Filename9 = "javadb.dll"
		$Filename10 = "mszlobm.dll"
		$Filename11 = "netfram.dll"
		$Filename12 = "netman.dll"
		$Filename13 = "ntdapie.dll"
		$Filename14 = "ntdelu.dll"
		$Filename15 = "ntobm.dll"
		$Filename16 = "odbm.dll"
		$Filename17 = "senss.dll"
		$Filename18 = "suddec.dll"
		$Filename19 = "tabcteng.dll"
		$Filename20 = "vmmreg32.dll"
		$Filename21 = "wininete.dll"
	condition:
		$MD51 or $Filename1 or $Filepath1 or $Filename2 or $Filename3 or $Filename4 or $Filename5 or $Filename6 or $Filename7 or $Filename8 or $Filename9 or $Filename10 or $Filename11 or $Filename12 or $Filename13 or $Filename14 or $Filename15 or $Filename16 or $Filename17 or $Filename18 or $Filename19 or $Filename20 or $Filename21
}