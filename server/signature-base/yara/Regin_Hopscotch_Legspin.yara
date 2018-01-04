rule Regin_Hopscotch_Legspin
{
	strings:
		$MD51 = "6c34031d7a5fc2b091b623981a8ae61c"
		$MD52 = "42eaf2ab25c9ead201f25ecbdc96fb60"
		$Filename1 = "dllhost.exe"
		$Filename2 = "dllhost.exe"
		$Filename3 = "svchost.exe"
		$MD53 = "29105f46e4d33f66fee346cfd099d1cc"
		$Filename4 = "advapi32.dll"
		$Filename5 = "kernel32.dll"
		$Filename6 = "msvcrt.dll"
		$Filename7 = "ntdll.dll"
		$Filename8 = "ntoskrnl.exe"
		$Filename9 = "win32k.sys"
		$Filename10 = "cmd.exe"
		$Filename11 = "ping.exe"
		$Filename12 = "ipconfig.exe"
		$Filename13 = "tracert.exe"
		$Filename14 = "netstat.exe"
		$Filename15 = "net.exe"
		$Filename16 = "user32.dll"
		$Filename17 = "gdi32.dll"
		$Filename18 = "shell32.dll"
		$Filename19 = "lsass.exe"
		$Registry1 = "HKLM\\SOFTWARE\\Microsoft\\Windows"
	condition:
		$MD51 or $MD52 or $Filename1 or $Filename2 or $Filename3 or $MD53 or $Filename4 or $Filename5 or $Filename6 or $Filename7 or $Filename8 or $Filename9 or $Filename10 or $Filename11 or $Filename12 or $Filename13 or $Filename14 or $Filename15 or $Filename16 or $Filename17 or $Filename18 or $Filename19 or $Registry1
}