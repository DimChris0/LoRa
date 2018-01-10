rule shady_rat_vanity
{
	strings:
		$Host1 = "vanityfair.com"
	condition:
		$Host1
}