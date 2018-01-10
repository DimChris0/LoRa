rule CrowdStrike_Flying_Kitten
{
	strings:
		$Host1 = "parmanpower.com"
		$Host2 = "usa.gov.us"
		$Host3 = "aeroconf2014.org"
		$Email1 = "keyvan.ajaxtm@gmail.com"
		$Filename1 = "IntelRapidStart.exe"
	condition:
		$Host1 or $Host2 or $Host3 or $Email1 or $Filename1
}