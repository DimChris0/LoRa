rule rpt_fin4
{
	strings:
		$URL1 = "http://forum.<domain>/redirect"
		$URL2 = "http://<domain>%2fforum%2fequities%2f375823902%2farticle"
		$Host1 = "www.junomaat81.us"
		$Host2 = "junomaat81.us"
		$Host3 = "lifehealthsanfrancisco2015.com"
		$Host4 = "ellismikepage.info"
		$Host5 = "rpgallerynow.info"
		$Host6 = "msoutexchange.us"
		$Host7 = "outlookscansafe.net"
		$Host8 = "outlookexchange.net"
		$Host9 = "lifehealthsanfrancisco2015.com"
		$Host10 = "dmforever.biz"
		$Host11 = "junomaat81.us"
		$Host12 = "nickgoodsite.co.uk"
	condition:
		$URL1 or $URL2 or $Host1 or $Host2 or $Host3 or $Host4 or $Host5 or $Host6 or $Host7 or $Host8 or $Host9 or $Host10 or $Host11 or $Host12
}