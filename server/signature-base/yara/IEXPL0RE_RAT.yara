rule IEXPL0RE_RAT
{
	strings:
		$Filename1 = "config.dll"
		$Filename2 = "config.dll"
		$Filepath1 = "C:\\Documents"
		$Filename3 = "svchost.exe"
		$Filename4 = "csv.exe"
		$Filename5 = "360tray.exe"
		$Filename6 = "svchost.exe"
		$Filename7 = "svchost.exe"
		$Filepath2 = "C:\\Documents"
		$Filepath3 = "C:\\Documents"
		$Filepath4 = "C:\\Documents"
		$Filepath5 = "C:\\Documents"
		$Filepath6 = "C:\\WINDOWS\\system\\lock.dat"
		$Filepath7 = "C:\\WINDOWS\\system\\MSMAPI32.SRG"
		$Filepath8 = "C:\\WINDOWS\\system32\\STREAM.SYS"
		$MD51 = "d7c826ac94522416a0aecf5b7a5d2afe"
		$MD52 = "66e1aff355c29c6f39b21aedbbed2d5c"
		$MD53 = "21a1ee58e4b543d7f2fa3b4022506029"
		$MD54 = "8d4e42982060d884e2b7bd257727fd7c"
		$MD55 = "d46d85777062afbcda02de68c063b877"
		$MD56 = "85e8c6ddcfa7e289be14324abbb7378d"
		$MD57 = "eb51b384fcbbe468a6877f569021c5d1"
		$MD58 = "8268297c1b38832c03f1c671e0a54a78"
		$Filename8 = "fxsst.dll"
		$Filename9 = "offscreen.dll"
		$Filename10 = "offsound.dll"
		$Filename11 = "off.dll"
	condition:
		$Filename1 or $Filename2 or $Filepath1 or $Filename3 or $Filename4 or $Filename5 or $Filename6 or $Filename7 or $Filepath2 or $Filepath3 or $Filepath4 or $Filepath5 or $Filepath6 or $Filepath7 or $Filepath8 or $MD51 or $MD52 or $MD53 or $MD54 or $MD55 or $MD56 or $MD57 or $MD58 or $Filename8 or $Filename9 or $Filename10 or $Filename11
}