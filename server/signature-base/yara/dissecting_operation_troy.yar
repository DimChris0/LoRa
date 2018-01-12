rule dissecting_operation_troy
{
	strings:
		$Host1 = "pastebin.com"
		$Email1 = "joseph.r.ulatoski@gmail.com"
		$Filename1 = "AgentBase.exe"
		$MD51 = "9263e40d9823aecf9388b64de34eae54"
		$MD52 = "db4bbdc36a78a8807ad9b15a562515c4"
		$MD53 = "5fcd6e1dace6b0599429d913850f0364"
		$MD54 = "f0e045210e3258dad91d7b6b4d64e7f3"
		$Filename2 = "bs.dll"
		$Filename3 = "HTTPSecurityProvider.dll"
		$Filepath1 = "E:\\Work\\BackUp\\2011\\nstar_1103\\BackDoor\\BsDll-up\\Release\\BsDll.pdb"
		$Filepath2 = "D:\\VMware\\eaglexp"
		$Filepath3 = "D:\\\\Chang\\\\vmshare\\\\Work\\\\BsDll-up\\\\Release\\\\BsDll.pdb"
		$Host2 = "foxlink.com"
		$Host3 = "edu.com"
		$Host4 = "-h1.bluethunder.co"
		$Host5 = "co.kr"
		$Host6 = "pe.kr"
		$Filepath4 = "Z:\\source\\1\\HttpTroy\\BsDll-up\\Release\\BsDll.pdb"
		$Filename4 = "chonanship.scr"
		$Filename5 = "SUpdate.exe"
		$Host7 = "sujewha.com"
		$Filepath5 = "Z:\\1Mission\\Team_Project"
		$Filepath6 = "E:\\Tong\\Work\\Op\\1Mission\\Team_Project"
		$Filepath7 = "D:\\Work\\Op\\Mission\\TeamProject"
		$Filepath8 = "Z:\\Work\\v3zip"
		$Filepath9 = "Z:\\Work\\v3unzip.c"
		$Filename6 = "payload32.dll"
		$Filename7 = "payload64.dll"
		$Filename8 = "svchost.exe"
		$Filename9 = "AhnlabUpdate.exe"
		$Filepath10 = "C:\\test\\BD_Installer_2010\\x64\\Release\\BD_Installer_2010.pdb"
		$Filepath11 = "Z:\\\\Work\\\\Make"
		$Filename10 = "RunCmd.exe"
		$Host8 = "take.chu.jp"
		$Host9 = "seung.us"
		$Host10 = "sarangbang.us"
		$Host11 = "christkingchurch.us"
		$Host12 = "djuna.cine21.com"
		$Host13 = "strider.pe.kr"
		$Host14 = "dochang.pe.kr"
		$Host15 = "kairoshairstory.com.au"
		$Host16 = "ejiweb.com"
		$Host17 = "dennisoneil.net"
		$Host18 = "daeilho.net"
		$Filename11 = "ip6ld.dll"
		$Filename12 = "81923.dll"
		$Filename13 = "Bs.dll"
		$Filename14 = "Ip6ld.dll"
		$Filename15 = "payload.dll"
		$Filename16 = "Payload.dll"
		$URL1 = "https://github.com/jonasschnelli/IRCClient"
		$URL2 = "http://www.wischik.com/lu/programmer/zip_utils.html"
		$Filename17 = "zip_utils.html"
		$Host19 = "www.wischik.com"
	condition:
		$Host1 or $Email1 or $Filename1 or $MD51 or $MD52 or $MD53 or $MD54 or $Filename2 or $Filename3 or $Filepath1 or $Filepath2 or $Filepath3 or $Host2 or $Host3 or $Host4 or $Host5 or $Host6 or $Filepath4 or $Filename4 or $Filename5 or $Host7 or $Filepath5 or $Filepath6 or $Filepath7 or $Filepath8 or $Filepath9 or $Filename6 or $Filename7 or $Filename8 or $Filename9 or $Filepath10 or $Filepath11 or $Filename10 or $Host8 or $Host9 or $Host10 or $Host11 or $Host12 or $Host13 or $Host14 or $Host15 or $Host16 or $Host17 or $Host18 or $Filename11 or $Filename12 or $Filename13 or $Filename14 or $Filename15 or $Filename16 or $URL1 or $URL2 or $Filename17 or $Host19
}rule dissecting_operation_troy
{
	strings:
		$Host1 = "pastebin.com"
		$Email1 = "joseph.r.ulatoski@gmail.com"
		$Filename1 = "AgentBase.exe"
		$MD51 = "9263e40d9823aecf9388b64de34eae54"
		$MD52 = "db4bbdc36a78a8807ad9b15a562515c4"
		$MD53 = "5fcd6e1dace6b0599429d913850f0364"
		$MD54 = "f0e045210e3258dad91d7b6b4d64e7f3"
		$Filename2 = "bs.dll"
		$Filename3 = "HTTPSecurityProvider.dll"
		$Filepath1 = "E:\\Work\\BackUp\\2011\\nstar_1103\\BackDoor\\BsDll-up\\Release\\BsDll.pdb"
		$Filepath2 = "D:\\VMware\\eaglexp"
		$Filepath3 = "D:\\\\Chang\\\\vmshare\\\\Work\\\\BsDll-up\\\\Release\\\\BsDll.pdb"
		$Host2 = "foxlink.com"
		$Host3 = "edu.com"
		$Host4 = "-h1.bluethunder.co"
		$Host5 = "co.kr"
		$Host6 = "pe.kr"
		$Filepath4 = "Z:\\source\\1\\HttpTroy\\BsDll-up\\Release\\BsDll.pdb"
		$Filename4 = "chonanship.scr"
		$Filename5 = "SUpdate.exe"
		$Host7 = "sujewha.com"
		$Filepath5 = "Z:\\1Mission\\Team_Project"
		$Filepath6 = "E:\\Tong\\Work\\Op\\1Mission\\Team_Project"
		$Filepath7 = "D:\\Work\\Op\\Mission\\TeamProject"
		$Filepath8 = "Z:\\Work\\v3zip"
		$Filepath9 = "Z:\\Work\\v3unzip.c"
		$Filename6 = "payload32.dll"
		$Filename7 = "payload64.dll"
		$Filename8 = "svchost.exe"
		$Filename9 = "AhnlabUpdate.exe"
		$Filepath10 = "C:\\test\\BD_Installer_2010\\x64\\Release\\BD_Installer_2010.pdb"
		$Filepath11 = "Z:\\\\Work\\\\Make"
		$Filename10 = "RunCmd.exe"
		$Host8 = "take.chu.jp"
		$Host9 = "seung.us"
		$Host10 = "sarangbang.us"
		$Host11 = "christkingchurch.us"
		$Host12 = "djuna.cine21.com"
		$Host13 = "strider.pe.kr"
		$Host14 = "dochang.pe.kr"
		$Host15 = "kairoshairstory.com.au"
		$Host16 = "ejiweb.com"
		$Host17 = "dennisoneil.net"
		$Host18 = "daeilho.net"
		$Filename11 = "ip6ld.dll"
		$Filename12 = "81923.dll"
		$Filename13 = "Bs.dll"
		$Filename14 = "Ip6ld.dll"
		$Filename15 = "payload.dll"
		$Filename16 = "Payload.dll"
		$URL1 = "https://github.com/jonasschnelli/IRCClient"
		$URL2 = "http://www.wischik.com/lu/programmer/zip_utils.html"
		$Filename17 = "zip_utils.html"
		$Host19 = "www.wischik.com"
	condition:
		$Host1 or $Email1 or $Filename1 or $MD51 or $MD52 or $MD53 or $MD54 or $Filename2 or $Filename3 or $Filepath1 or $Filepath2 or $Filepath3 or $Host2 or $Host3 or $Host4 or $Host5 or $Host6 or $Filepath4 or $Filename4 or $Filename5 or $Host7 or $Filepath5 or $Filepath6 or $Filepath7 or $Filepath8 or $Filepath9 or $Filename6 or $Filename7 or $Filename8 or $Filename9 or $Filepath10 or $Filepath11 or $Filename10 or $Host8 or $Host9 or $Host10 or $Host11 or $Host12 or $Host13 or $Host14 or $Host15 or $Host16 or $Host17 or $Host18 or $Filename11 or $Filename12 or $Filename13 or $Filename14 or $Filename15 or $Filename16 or $URL1 or $URL2 or $Filename17 or $Host19
}