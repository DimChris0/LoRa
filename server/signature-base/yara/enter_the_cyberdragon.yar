rule enter_the_cyberdragon
{
	strings:
		$URL1 = "http://www.vanityfair.com/culture/features/2011/09/chinese-hacking-201109"
		$Host1 = "www.vanityfair.com"
	condition:
		$URL1 or $Host1
}