rule winnti_pharmaceutical
{
	strings:
		$Filename1 = "w64.dll"
		$Filepath1 = "C:\\Windows\\TEMP\\tmpCCD.tmp"
		$Filename2 = "ServiceAdobe.dll"
		$MD51 = "8e61219b18d36748ce956099277cc29b"
		$MD52 = "5979cf5018c03be2524b87b7dda64a1a"
		$MD53 = "ac9b247691b1036a1cdb4aaf37bea97f"
	condition:
		$Filename1 or $Filepath1 or $Filename2 or $MD51 or $MD52 or $MD53
}