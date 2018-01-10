rule FTA____Shamoon
{
	strings:
		$URL1 = "http://blog.seculert.com/2012/08/shamoon-two-stage-targeted-attack.html"
		$URL2 = "http://www.huffingtonpost.com/2012/10/11/shamoon-virus-leon"
		$Filename1 = "shamoon-two-stage-targeted-attack.html"
		$Filename2 = "panetta_n_1960113.html"
		$Host1 = "blog.seculert.com"
	condition:
		$URL1 or $URL2 or $Filename1 or $Filename2 or $Host1
}