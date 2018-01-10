rule Trojan_APT_BaneChant
{
	strings:
		$Filename1 = "Jihad.doc"
		$Host1 = "ow.ly"
		$URL1 = "hxxp://symbisecure.com/update/winword.pkg"
		$Host2 = "symbisecure.com"
		$URL2 = "hxxp://kibber.no-ip.org/adserv/logo.jpg"
		$Filename2 = "logo.jpg"
		$Host3 = "kibber.no-ip.org"
		$Filepath1 = "C:\\ProgramData\\Google2\\GoogleUpdate.exe"
		$Filename3 = "GoogleUpdate.exe"
		$URL3 = "hxxp://symbisecure.com/adserv/get.php"
	condition:
		$Filename1 or $Host1 or $URL1 or $Host2 or $URL2 or $Filename2 or $Host3 or $Filepath1 or $Filename3 or $URL3
}