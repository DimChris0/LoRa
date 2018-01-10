rule Regin_Hopscotch_Legspin
{
	strings:
		$MD51 = "6c34031d7a5fc2b091b623981a8ae61c"
		$MD52 = "42eaf2ab25c9ead201f25ecbdc96fb60"
		$Filename1 = "dllhost.exe"
		$Filename2 = "svchost.exe"
		$MD53 = "29105f46e4d33f66fee346cfd099d1cc"
		$Filename3 = "advapi32.dll"
		$Filename4 = "kernel32.dll"
		$Filename5 = "msvcrt.dll"
		$Filename6 = "ntdll.dll"
		$Filename7 = "ntoskrnl.exe"
		$Filename8 = "win32k.sys"
		$Filename9 = "cmd.exe"
		$Filename10 = "ping.exe"
		$Filename11 = "ipconfig.exe"
		$Filename12 = "tracert.exe"
		$Filename13 = "netstat.exe"
		$Filename14 = "net.exe"
		$Filename15 = "user32.dll"
		$Filename16 = "gdi32.dll"
		$Filename17 = "shell32.dll"
		$Filename18 = "lsass.exe"
		$Registry1 = "HKLM\\SOFTWARE\\Microsoft\\Windows"
	condition:
		$MD51 or $MD52 or $Filename1 or $Filename2 or $MD53 or $Filename3 or $Filename4 or $Filename5 or $Filename6 or $Filename7 or $Filename8 or $Filename9 or $Filename10 or $Filename11 or $Filename12 or $Filename13 or $Filename14 or $Filename15 or $Filename16 or $Filename17 or $Filename18 or $Registry1
}