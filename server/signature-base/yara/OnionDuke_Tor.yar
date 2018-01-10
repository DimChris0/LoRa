rule OnionDuke_Tor
{
	strings:
		$SHA11 = "a75995f94854dea8799650a2f4a97980b71199d2"
		$SHA12 = "b491c14d8cfb48636f6095b7b16555e9a575d57f"
		$SHA13 = "d433f281cf56015941a1c2cb87066ca62ea1db37"
		$Host1 = "overpict.com"
		$Host2 = "airtravelabroad.com"
		$Host3 = "beijingnewsblog.net"
		$Host4 = "grouptumbler.com"
		$Host5 = "leveldelta.com"
		$Host6 = "nasdaqblog.net"
		$Host7 = "natureinhome.com"
		$Host8 = "nestedmail.com"
		$Host9 = "nostressjob.com"
		$Host10 = "nytunion.com"
		$Host11 = "oilnewsblog.com"
		$Host12 = "sixsquare.net"
		$Host13 = "ustradecomp.com"
	condition:
		$SHA11 or $SHA12 or $SHA13 or $Host1 or $Host2 or $Host3 or $Host4 or $Host5 or $Host6 or $Host7 or $Host8 or $Host9 or $Host10 or $Host11 or $Host12 or $Host13
}