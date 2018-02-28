rule circl_analysisreport_miniduke_stage3_public
{
	strings:
		$Host1 = "circl.lu"
		$Host2 = "www.circl.lu"
		$Email1 = "info@circl.lu"
		$SHA11 = "de8e9def2553f4d211cc0b34a3972d9814f156aa"
		$Host3 = "www.oberhumer.com"
		$SHA2561 = "a1015f0b99106ae2852d740f366e15c1d5c711f57680a2f04be0283e8310f69e"
		$SHA2562 = "b61d409b6c1066e0c1fc4fe15f6f367be31fa2cc555cfc0ef7eeb8e5759380c0"
		$MD51 = "1e1b0d16a16cf5c7f3a7c053ce78f515"
		$MD52 = "1a2edd2db71fd41e963011da8caf26cc"
		$Filename1 = "cosmicduke_whitepaper.pdf"
		$Registry1 = "HKCU\\Software\\Microsoft\\ApplicationManager"
		$IP1 = "173.194.70.101"
		$IP2 = "200.63.46.33"
		$IP3 = "200.63.46.23"
		$Host4 = "news.grouptumbler.com"
		$Host5 = "bgpranking.circl.lu"
	condition:
		$Host1 or $Host2 or $Email1 or $SHA11 or $Host3 or $SHA2561 or $SHA2562 or $MD51 or $MD52 or $Filename1 or $Registry1 or $IP1 or $IP2 or $IP3 or $Host4 or $Host5
}