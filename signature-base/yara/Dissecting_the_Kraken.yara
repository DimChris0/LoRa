rule Dissecting_the_Kraken
{
	strings:
		$Filename1 = "dissecting-the-kraken.html"
		$Filename2 = "dissecting-the-kraken.html"
		$CVE1 = "CVE-2012-0158"
		$CVE2 = "CVE-2012-0158"
		$MD51 = "08E834B6D4123F0AEA27D042FCEAF992"
		$Filepath1 = "C:\\Program"
		$Filepath2 = "C:\\Program"
		$Filepath3 = "C:\\WINDOWS\\system32\\VBoxtray.exe"
		$Filename3 = "VBoxtray.exe"
		$Filename4 = "dissecting-the-kraken.html"
		$MD52 = "3917107778F928A6F65DB34553D5082A"
		$Filename5 = "dissecting-the-kraken.html"
		$Filename6 = "dissecting-the-kraken.html"
		$Registry1 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Windows"
		$Filename7 = "dissecting-the-kraken.html"
		$Filename8 = "dissecting-the-kraken.html"
	condition:
		$Filename1 or $Filename2 or $CVE1 or $CVE2 or $MD51 or $Filepath1 or $Filepath2 or $Filepath3 or $Filename3 or $Filename4 or $MD52 or $Filename5 or $Filename6 or $Registry1 or $Filename7 or $Filename8
}