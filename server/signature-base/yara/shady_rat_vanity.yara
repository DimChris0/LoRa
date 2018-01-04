rule shady_rat_vanity
{
	strings:
		$Host1 = "vanityfair.com"
		$Host2 = "vanityfair.com"
	condition:
		$Host1 or $Host2
}