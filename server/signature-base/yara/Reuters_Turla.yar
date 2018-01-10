rule Reuters_Turla
{
	strings:
		$Host1 = "www.reutersreprints.com"
	condition:
		$Host1
}