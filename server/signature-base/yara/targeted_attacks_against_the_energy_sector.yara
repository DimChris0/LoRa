rule targeted_attacks_against_the_energy_sector
{
	strings:
		$CVE1 = "CVE-2010-2568"
		$Filename1 = "AVP.dll"
		$Filename2 = "clbcatq.dll"
		$Filename3 = "AVP.dll"
		$Filename4 = "pdf.exe"
		$Filename5 = "E-Book.pdf.exe"
		$Filename6 = "BusinessWeek.pdf.exe"
		$Filename7 = "E-Paper.pdf.exe"
		$Filename8 = "Edition.pdf.exe"
		$Filename9 = "Print.pdf.exe"
		$Filename10 = "Greek.exe"
		$Filename11 = "Translator.exe"
		$Filename12 = "Desktop.exe"
		$Filename13 = "iPlayer.exe"
		$Filename14 = "Desktop.exe"
		$Host1 = "updates.zyns.com"
		$Host2 = "amazoaws.dyndns-office.com"
		$Host3 = "msupdate.3utilities.com"
		$Filename15 = "pdf.exe"
		$Filename16 = "com.exe"
	condition:
		$CVE1 or $Filename1 or $Filename2 or $Filename3 or $Filename4 or $Filename5 or $Filename6 or $Filename7 or $Filename8 or $Filename9 or $Filename10 or $Filename11 or $Filename12 or $Filename13 or $Filename14 or $Host1 or $Host2 or $Host3 or $Filename15 or $Filename16
}