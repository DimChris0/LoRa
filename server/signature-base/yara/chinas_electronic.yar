rule chinas_electronic
{
	strings:
		$URL1 = "http://full.mingpaonews.com/20030312"
		$Host1 = "full.mingpaonews.com"
		$Host2 = "www.fcw.com"
		$Host3 = "www.iht.com"
	condition:
		$URL1 or $Host1 or $Host2 or $Host3
}