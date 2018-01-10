rule the_elderwood_project
{
	strings:
		$CVE1 = "CVE-2012-0779"
		$CVE2 = "CVE-2012-1875"
		$CVE3 = "CVE-2012-1889"
		$CVE4 = "CVE-2012-1535"
		$URL1 = "http://twitter.com/threatintel"
		$IP1 = "71.6.217.131"
		$Host1 = "qwby.gownsman.com"
		$Host2 = "wwwcnas.org"
		$Host3 = "gate-usa.com"
		$Host4 = "3dvideo.ru"
		$Host5 = "wt.ikwb.com"
		$Host6 = "svr01.passport.serveuser.com"
		$Host7 = "zfcay1751.chinaw3.com"
		$Host8 = "web.cyut.edu.tw"
		$Host9 = "srv001.proxydns.com"
		$Host10 = "help.2012hi.hk"
		$Host11 = "0207.gm.jetos.com"
		$Host12 = "javaupdate.freeddns.com"
		$Host13 = "yours.microtrendsoft.com"
		$Host14 = "cpu.edu.tw"
		$Host15 = "glogin.ddns.us"
		$Host16 = "download.msdnblog.com"
		$Host17 = "dd.pst.qpoe.com"
		$CVE5 = "CVE-2010-0249"
		$CVE6 = "CVE-2011-0609"
		$CVE7 = "CVE-2011-2110"
		$CVE8 = "CVE-2011-0611"
	condition:
		$CVE1 or $CVE2 or $CVE3 or $CVE4 or $URL1 or $IP1 or $Host1 or $Host2 or $Host3 or $Host4 or $Host5 or $Host6 or $Host7 or $Host8 or $Host9 or $Host10 or $Host11 or $Host12 or $Host13 or $Host14 or $Host15 or $Host16 or $Host17 or $CVE5 or $CVE6 or $CVE7 or $CVE8
}