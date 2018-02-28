rule GData_Uroburos_RedPaper_EN_v1
{
	strings:
		$URL1 = "http://www.mspaintadventures.com/?s=6"
		$Filename1 = "inj_snake_Win32.dll"
		$Filename2 = "inj_snake_Win64.dll"
		$Host1 = "www.mspaintadventures.com"
		$Filename3 = "Ultra3.sys"
		$Filename4 = "msw32.sys"
		$Filename5 = "vstor32.sys"
		$Registry1 = "HKLM\\System\\CurrentControlSet\\Services\\Ultra3"
		$Filename6 = "inj_services_Win32.dll"
		$Host2 = "vnd.ms"
		$URL2 = "http://www.reuters.com/article/2011/06/17/us-usa-cybersecurity-worm-idUSTRE75F5TB20110617"
		$SHA2561 = "BF1CFC65B78F5222D35DC3BD2F0A87C9798BCE5A48348649DD271CE395656341"
		$MD51 = "320F4E6EE421C1616BD058E73CFEA282"
	condition:
		$URL1 or $Filename1 or $Filename2 or $Host1 or $Filename3 or $Filename4 or $Filename5 or $Registry1 or $Filename6 or $Host2 or $URL2 or $SHA2561 or $MD51
}