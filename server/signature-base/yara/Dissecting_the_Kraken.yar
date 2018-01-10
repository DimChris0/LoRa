rule Dissecting_the_Kraken
{
	strings:
		$Filename1 = "dissecting-the-kraken.html"
		$CVE1 = "CVE-2012-0158"
		$MD51 = "08E834B6D4123F0AEA27D042FCEAF992"
		$Filepath1 = "C:\\Program"
		$Filepath2 = "C:\\WINDOWS\\system32\\VBoxtray.exe"
		$Filename2 = "VBoxtray.exe"
		$MD52 = "3917107778F928A6F65DB34553D5082A"
		$Registry1 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Windows"
	condition:
		$Filename1 or $CVE1 or $MD51 or $Filepath1 or $Filepath2 or $Filename2 or $MD52 or $Registry1
}rule Dissecting_the_Kraken
{
	strings:
		$Filename1 = "dissecting-the-kraken.html"
		$CVE1 = "CVE-2012-0158"
		$MD51 = "08E834B6D4123F0AEA27D042FCEAF992"
		$Filepath1 = "C:\\Program"
		$Filepath2 = "C:\\WINDOWS\\system32\\VBoxtray.exe"
		$Filename2 = "VBoxtray.exe"
		$MD52 = "3917107778F928A6F65DB34553D5082A"
		$Registry1 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Windows"
	condition:
		$Filename1 or $CVE1 or $MD51 or $Filepath1 or $Filepath2 or $Filename2 or $MD52 or $Registry1
}