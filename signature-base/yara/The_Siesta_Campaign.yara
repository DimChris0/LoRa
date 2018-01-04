rule The_Siesta_Campaign
{
	strings:
		$SHA11 = "014542eafb792b98196954373b3fd13e60cb94fe"
		$URL1 = "http://www.micro{BLOCKED"
		$Filename1 = "index.html"
		$Filename2 = "2014.exe"
		$Filename3 = "UIODsevr.exe"
		$Host1 = "163.com"
	condition:
		$SHA11 or $URL1 or $Filename1 or $Filename2 or $Filename3 or $Host1
}