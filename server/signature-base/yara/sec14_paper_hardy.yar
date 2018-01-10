rule sec_paper_hardy
{
	strings:
		$URL1 = "https://www.hex-rays.com/products/ida"
		$URL2 = "http://www.metasploit.com"
		$Host1 = "www.ollydbg.de"
		$URL3 = "https://tibetaction.net/detach-from"
		$URL4 = "https://citizenlab/targeted-threats"
		$Filename1 = "invitation.doc"
		$Filename2 = "fire.doc"
		$Host2 = "tibetaction.net"
		$Email1 = "fdc2008paris@gmail.com"
		$Email2 = "nimaciran@gmail.com"
		$Filename3 = "home.doc"
		$Host3 = "tibetancareers.org"
		$Host4 = "www.tibet.jobeestan.com"
		$Email3 = "palden.sangpo@tibetancareers.org"
		$Email4 = "chengli.brookings@aol.com"
		$Email5 = "albano_kuqo@gmx.com"
	condition:
		$URL1 or $URL2 or $Host1 or $URL3 or $URL4 or $Filename1 or $Filename2 or $Host2 or $Email1 or $Email2 or $Filename3 or $Host3 or $Host4 or $Email3 or $Email4 or $Email5
}