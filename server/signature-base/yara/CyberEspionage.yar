rule CyberEspionage
{
	strings:
		$Host1 = "www.oops.com"
		$Email1 = "jim.impoco@thomsonreuters.com"
		$Email2 = "brian.grow@thomsonreuters.com"
		$Email3 = "mark.hosenball@thomsonreuters.com"
	condition:
		$Host1 or $Email1 or $Email2 or $Email3
}