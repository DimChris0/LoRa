rule Reuters_Turla
{
	strings:
		$Host1 = "www.reutersreprints.com"
		$Host2 = "www.reutersreprints.com"
	condition:
		$Host1 or $Host2
}