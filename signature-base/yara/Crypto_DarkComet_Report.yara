rule Crypto_DarkComet_Report
{
	strings:
		$URL1 = "http://www.contextis.com/research/blog/darkcometrat"
		$Host1 = "newrat2.no"
		$Host2 = "ip.org"
		$MD51 = "63f2ed5d2ee50e90cda809f2ac740244"
		$MD52 = "1C638B4887FFE980B0B9AE72B1EA40A3"
		$Filepath1 = "C:\\WINDOWS\\system32\\cmd.exe"
		$IP1 = "192.10.8.64"
		$IP2 = "192.1.167.30"
		$Filename1 = "cmd.exe"
		$SHA2561 = "185CB63BA31EA7C967297252432E5A7CFC96B261EB7EF4742533CEBF37A9C081"
		$SHA2562 = "185CB63BA503B9C967297252432E5A7CFC96B261EB7EF4742533CEBF37A9C081"
	condition:
		$URL1 or $Host1 or $Host2 or $MD51 or $MD52 or $Filepath1 or $IP1 or $IP2 or $Filename1 or $SHA2561 or $SHA2562
}