rule targeted_attacks_against_the_energy_sector
{
	strings:
		$CVE1 = "CVE-2010-2568"
		$Filename1 = "AVP.dll"
		$Filename2 = "clbcatq.dll"
		$Filename3 = "pdf.exe"
		$Filename4 = "E-Book.pdf.exe"
		$Filename5 = "BusinessWeek.pdf.exe"
		$Filename6 = "E-Paper.pdf.exe"
		$Filename7 = "Edition.pdf.exe"
		$Filename8 = "Print.pdf.exe"
		$Filename9 = "Greek.exe"
		$Filename10 = "Translator.exe"
		$Filename11 = "Desktop.exe"
		$Filename12 = "iPlayer.exe"
		$Host1 = "updates.zyns.com"
		$Host2 = "amazoaws.dyndns-office.com"
		$Host3 = "msupdate.3utilities.com"
		$Filename13 = "com.exe"
	condition:
		$CVE1 or $Filename1 or $Filename2 or $Filename3 or $Filename4 or $Filename5 or $Filename6 or $Filename7 or $Filename8 or $Filename9 or $Filename10 or $Filename11 or $Filename12 or $Host1 or $Host2 or $Host3 or $Filename13
}