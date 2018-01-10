rule ByeBye_Shell_target
{
	strings:
		$Registry1 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced"
		$Registry2 = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\Folder\\Hidden\\SHOWALL"
		$MD51 = "8b4224dac114a9b8433913a1977f88b2"
		$MD52 = "469cf94c457c17d8f24dacf9f9d41f33"
		$MD53 = "6b349e439a17c4b66fb2a25965432aa9"
		$MD54 = "d36da5c48d8fb7ee8c736ae183bf3f8a"
		$Filename1 = "cmd.exe"
		$IP1 = "2.5.29.1"
		$IP2 = "46.165.207.134"
		$IP3 = "46.165.207.255"
		$Filepath1 = "C:\\Documents"
	condition:
		$Registry1 or $Registry2 or $MD51 or $MD52 or $MD53 or $MD54 or $Filename1 or $IP1 or $IP2 or $IP3 or $Filepath1
}