rule OnionDuke_Tor
{
	strings:
		$SHA11 = "a75995f94854dea8799650a2f4a97980b71199d2"
		$SHA12 = "b491c14d8cfb48636f6095b7b16555e9a575d57f"
		$SHA13 = "d433f281cf56015941a1c2cb87066ca62ea1db37"
		$Host1 = "overpict.com"
		$Host2 = "overpict.com"
		$Host3 = "airtravelabroad.com"
		$Host4 = "beijingnewsblog.net"
		$Host5 = "grouptumbler.com"
		$Host6 = "leveldelta.com"
		$Host7 = "nasdaqblog.net"
		$Host8 = "natureinhome.com"
		$Host9 = "nestedmail.com"
		$Host10 = "nostressjob.com"
		$Host11 = "nytunion.com"
		$Host12 = "oilnewsblog.com"
		$Host13 = "sixsquare.net"
		$Host14 = "ustradecomp.com"
		$Host15 = "leveldelta.com"
		$Host16 = "grouptumbler.com"
		$SHA14 = "a75995f94854dea8799650a2f4a97980b71199d2"
		$SHA15 = "b491c14d8cfb48636f6095b7b16555e9a575d57f"
		$SHA16 = "d433f281cf56015941a1c2cb87066ca62ea1db37"
	condition:
		$SHA11 or $SHA12 or $SHA13 or $Host1 or $Host2 or $Host3 or $Host4 or $Host5 or $Host6 or $Host7 or $Host8 or $Host9 or $Host10 or $Host11 or $Host12 or $Host13 or $Host14 or $Host15 or $Host16 or $SHA14 or $SHA15 or $SHA16
}