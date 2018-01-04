rule apt29_hammertoss_stealthy_tactics_define_a
{
	strings:
		$MD51 = "d3109c83e07dd5d7fe032dc80c581d08"
		$Filename1 = "tDiscoverer.exe"
		$Host1 = "doctorhandbook.com"
		$URL1 = "hxxps://twitter.com/1abBob52b"
		$Host2 = "doctorhandbook.com"
		$Host3 = "doctorhandbook.com"
		$SHA11 = "42e6da9a08802b5ce5d1f754d4567665637b47bc"
		$URL2 = "hxxp://www.doctorhandbook.com"
		$URL3 = "http://www.intego.com/mac-security-blog/flashback-mac-malware-uses-twitter-as-command-and-control-center"
		$URL4 = "http://content.usatoday.com/communities/technologylive/post/2009/08/68497133/1#.VbJVi4q9_Vs"
		$Filename2 = "MiniDuke_Paper_Final.pdf"
		$Host4 = "twitter.com"
		$Host5 = "www.doctorhandbook.com"
		$Host6 = "www.welivesecurity.com"
		$Host7 = "www.intego.com"
		$Host8 = "content.usatoday.com"
		$MD52 = "d3109c83e07dd5d7fe032dc80c581d08"
		$URL5 = "https://www.fireeye.com/reports.html"
		$Filename3 = "reports.html"
	condition:
		$MD51 or $Filename1 or $Host1 or $URL1 or $Host2 or $Host3 or $SHA11 or $URL2 or $URL3 or $URL4 or $Filename2 or $Host4 or $Host5 or $Host6 or $Host7 or $Host8 or $MD52 or $URL5 or $Filename3
}