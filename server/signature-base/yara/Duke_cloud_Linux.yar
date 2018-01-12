rule Duke_cloud_Linux
{
	strings:
		$Filepath1 = "C:\\DropperSolution\\Droppers\\Projects\\Drop_v2\\Release\\Drop_v2.pdb"
		$SHA11 = "28d29c702fdf3c16f27b33f3e32687dd82185e8b"
		$SHA12 = "04299c0b549d4a46154e0a754dda2bc9e43dff76"
		$SHA13 = "2f53bfcd2016d506674d0a05852318f9e8188ee1"
		$SHA14 = "317bde14307d8777d613280546f47dd0ce54f95b"
		$SHA15 = "476099ea132bf16fa96a5f618cb44f87446e3b02"
		$SHA16 = "4800d67ea326e6d037198abd3d95f4ed59449313"
		$SHA17 = "52d44e936388b77a0afdb21b099cf83ed6cbaa6f"
		$SHA18 = "6a3c2ad9919ad09ef6cdffc80940286814a0aa2c"
		$SHA19 = "78fbdfa6ba2b1e3c8537be48d9efc0c47f417f3c"
		$SHA110 = "9f5b46ee0591d3f942ccaa9c950a8bff94aa7a0f"
		$SHA111 = "bfe26837da22f21451f0416aa9d241f98ff1c0f8"
		$SHA112 = "c16529dbc2987be3ac628b9b413106e5749999ed"
		$SHA113 = "cc15924d37e36060faa405e5fa8f6ca15a3cace2"
		$SHA114 = "dea6e89e36cf5a4a216e324983cc0b8f6c58eaa8"
		$SHA115 = "e33e6346da14931735e73f544949a57377c6b4a0"
		$SHA116 = "ed0cf362c0a9de96ce49c841aa55997b4777b326"
		$SHA117 = "f54f4e46f5f933a96650ca5123a4c41e115a9f61"
		$SHA118 = "f97c5e8d018207b1d546501fe2036adfbf774cfd"
		$URL1 = "hxxps://cognimuse.cs.ntua.gr/search.php"
		$URL2 = "hxxps://portal.sbn.co.th/rss.php"
		$URL3 = "hxxps://97.75.120.45/news/archive.php"
		$URL4 = "hxxps://58.80.109.59/plugins/search.php"
		$URL5 = "hxxp://flockfilmseries.com/eFax/incoming/5442.ZIP"
		$URL6 = "hxxp://www.recordsmanagementservices.com/eFax/incoming/150721/5442.ZIP"
		$URL7 = "hxxp://files.counseling.org/eFax/incoming/150721/5442.ZIP"
		$IP1 = "97.75.120.45"
		$IP2 = "58.80.109.59"
		$Host1 = "cognimuse.cs.ntua.gr"
		$Host2 = "portal.sbn.co.th"
		$Host3 = "flockfilmseries.com"
		$Host4 = "www.recordsmanagementservices.com"
		$Host5 = "files.counseling.org"
	condition:
		$Filepath1 or $SHA11 or $SHA12 or $SHA13 or $SHA14 or $SHA15 or $SHA16 or $SHA17 or $SHA18 or $SHA19 or $SHA110 or $SHA111 or $SHA112 or $SHA113 or $SHA114 or $SHA115 or $SHA116 or $SHA117 or $SHA118 or $URL1 or $URL2 or $URL3 or $URL4 or $URL5 or $URL6 or $URL7 or $IP1 or $IP2 or $Host1 or $Host2 or $Host3 or $Host4 or $Host5
}