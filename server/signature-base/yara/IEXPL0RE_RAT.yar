rule IEXPLRE_RAT
{
	strings:
		$Filename1 = "config.dll"
		$Filepath1 = "C:\\Documents"
		$Filename2 = "svchost.exe"
		$Filename3 = "csv.exe"
		$Filename4 = "360tray.exe"
		$Filepath2 = "C:\\WINDOWS\\system\\lock.dat"
		$Filepath3 = "C:\\WINDOWS\\system\\MSMAPI32.SRG"
		$Filepath4 = "C:\\WINDOWS\\system32\\STREAM.SYS"
		$MD51 = "d7c826ac94522416a0aecf5b7a5d2afe"
		$MD52 = "66e1aff355c29c6f39b21aedbbed2d5c"
		$MD53 = "21a1ee58e4b543d7f2fa3b4022506029"
		$MD54 = "8d4e42982060d884e2b7bd257727fd7c"
		$MD55 = "d46d85777062afbcda02de68c063b877"
		$MD56 = "85e8c6ddcfa7e289be14324abbb7378d"
		$MD57 = "eb51b384fcbbe468a6877f569021c5d1"
		$MD58 = "8268297c1b38832c03f1c671e0a54a78"
		$Filename5 = "fxsst.dll"
		$Filename6 = "offscreen.dll"
		$Filename7 = "offsound.dll"
		$Filename8 = "off.dll"
	condition:
		$Filename1 or $Filepath1 or $Filename2 or $Filename3 or $Filename4 or $Filepath2 or $Filepath3 or $Filepath4 or $MD51 or $MD52 or $MD53 or $MD54 or $MD55 or $MD56 or $MD57 or $MD58 or $Filename5 or $Filename6 or $Filename7 or $Filename8
}