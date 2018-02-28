rule Aided_Frame_Aided_Direction
{
	strings:
		$URL1 = "http://103.27.108.45/img/js.php"
		$URL2 = "hxxp://103.27.108.45/img/js.php"
		$IP1 = "103.27.108.45"
		$MD51 = "118fa558a6b5020b078739ef7bdac3a1"
		$Filename1 = "chrome.exe"
		$MD52 = "09d0478591d4f788cb3e5ea416c25237"
		$MD53 = "82B582589D4A59BE0720F088ACAC67A3"
		$MD54 = "581AE6B6ABAFD73AC85B1AEFBDB2555F"
		$IP2 = "115.126.62.100"
		$Host1 = "quakegoogle.servequake.com"
		$Host2 = "assign.ddnsking.com"
		$Host3 = "picsgoogle.servepics.com"
		$SHA2561 = "82a98c88d3dd57a6ebc0fe7167a86875ed52ebddc6374ad640407efec01b1393"
	condition:
		$URL1 or $URL2 or $IP1 or $MD51 or $Filename1 or $MD52 or $MD53 or $MD54 or $IP2 or $Host1 or $Host2 or $Host3 or $SHA2561
}