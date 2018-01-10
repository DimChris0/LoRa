rule Palebot_Palestinian_credentials
{
	strings:
		$URL1 = "http://www.facebook.com"
		$URL2 = "https://portal.iugaza.edu.ps"
		$Filename1 = "svcshost.exe"
		$Filename2 = "svchost.exe"
		$Host1 = "portal.iugaza.edu.ps"
		$URL3 = "https://www.google.com/accounts"
		$URL4 = "http://www.fatehforums.com"
		$URL5 = "http://portal.iugaza.edu.ps"
		$URL6 = "https://login.yahoo.com/config/login"
		$URL7 = "https://www.google.com/accounts/service"
		$URL8 = "https://my.screenname.aol.com/_cqr/login.psp"
		$URL9 = "http://myaccount.jawwal.ps"
		$URL10 = "http://moneybookers.com"
		$URL11 = "http://mail.mtit.pna.ps/src/login.php"
		$Filename3 = "aylol.doc"
		$Host2 = "www.fatehforums.com"
		$Host3 = "myaccount.jawwal.ps"
		$Host4 = "www.myspace.com"
		$Host5 = "moneybookers.com"
		$Host6 = "mail.mtit.pna.ps"
		$Host7 = "www.alsbah.net"
		$MD51 = "7f3b74c9274f501bf0d9ded414b62f80"
		$MD52 = "25f758425fcea95ea07488e13f07e005"
		$MD53 = "1954622c1fe142200ad06eec12291fcd"
	condition:
		$URL1 or $URL2 or $Filename1 or $Filename2 or $Host1 or $URL3 or $URL4 or $URL5 or $URL6 or $URL7 or $URL8 or $URL9 or $URL10 or $URL11 or $Filename3 or $Host2 or $Host3 or $Host4 or $Host5 or $Host6 or $Host7 or $MD51 or $MD52 or $MD53
}