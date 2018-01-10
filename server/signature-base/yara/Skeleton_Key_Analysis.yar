rule Skeleton_Key_Analysis
{
	strings:
		$Filename1 = "ole64.dll"
		$MD51 = "bf45086e6334f647fda33576e2a05826"
		$SHA11 = "5083b17ccc50dd0557dfc544f84e2ab55d6acd92"
		$SHA12 = "ad61e8daeeba43e442514b177a1b41ad4b7c6727"
		$Filename2 = "msuta64.dll"
		$Filename3 = "ole.dll"
		$Filename4 = "ole32.dll"
		$MD52 = "66da7ed621149975f6e643b4f9886cfd"
		$Filepath1 = "C:\\WINDOWS\\system32"
		$Filename5 = "PSEXESVC.exe"
		$Filename6 = "cryptdll.dll"
		$Filename7 = "samsrv.dll"
		$Filename8 = "PsExec.exe"
		$Filename9 = "rundll32.exe"
		$Filename10 = "lsass.exe"
		$Filename11 = "HookDC.dll"
	condition:
		$Filename1 or $MD51 or $SHA11 or $SHA12 or $Filename2 or $Filename3 or $Filename4 or $MD52 or $Filepath1 or $Filename5 or $Filename6 or $Filename7 or $Filename8 or $Filename9 or $Filename10 or $Filename11
}