rule _10535_798405_Annex87_CyberAttacks
{
	strings:
		$Host1 = "www.georgiaupdate.gov.ge"
		$Host2 = "www.president.gov.ge"
		$Host3 = "president.gov.ge"
		$Host4 = "www.apsny.ge"
		$Host5 = "mfa.gov.ge"
		$Host6 = "mod.gov.ge"
		$Host7 = "stopgeorgia.ru"
		$Host8 = "stopgeorgia.info"
		$IP1 = "79.135.167.49"
		$IP2 = "79.135.167.22"
		$Filename1 = "name.avi.exe"
		$Host9 = "cybersecurity.ru"
		$Host10 = "thecanadianmeds.com"
		$IP3 = "62.168.168.9"
		$IP4 = "207.10.234.244"
		$Host11 = "www.saesa.gov.ge"
		$Host12 = "www.parliament.ge"
		$Host13 = "www.skandaly.ru"
		$Host14 = "googlecomaolcomyahoocomaboutcom.net"
		$Host15 = "hacker.ru"
		$Host16 = "kavkaz.org"
		$Host17 = "chechenpress.com"
		$Host18 = "kavkazcenter.com"
	condition:
		$Host1 or $Host2 or $Host3 or $Host4 or $Host5 or $Host6 or $Host7 or $Host8 or $IP1 or $IP2 or $Filename1 or $Host9 or $Host10 or $IP3 or $IP4 or $Host11 or $Host12 or $Host13 or $Host14 or $Host15 or $Host16 or $Host17 or $Host18
}