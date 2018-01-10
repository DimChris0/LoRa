rule Gholee_Protective_Edge_themed_spear_phishing_campaign
{
	strings:
		$URL1 = "http://www.clearskysec.com/gholee-a-protective"
		$Host1 = "www.clearskysec.com"
		$MD51 = "d0c3f4c9896d41a7c42737134ffb4c2e"
		$Filename1 = "cmd.exe"
		$MD52 = "48573a150562c57742230583456b4c02"
		$IP1 = "83.170.33.60"
		$Host2 = "coreimpactagent.net"
		$IP2 = "83.170.33.37"
		$Filename2 = "67.exe"
		$MD53 = "916be1b609ed3dc80e5039a1d8102e82"
		$URL2 = "http://www.clearskysec.com/wp-content/uploads/2014/09/2.png"
		$URL3 = "http://www.clearskysec.com/wp-content/uploads/2014/09/5.png"
		$URL4 = "http://www.clearskysec.com/wp-content/uploads/2014/09/6.png"
		$URL5 = "http://www.clearskysec.com/wp-content/uploads/2014/09/1.png"
		$URL6 = "http://www.clearskysec.com/wp-content/uploads/2014/09/7.png"
		$URL7 = "http://www.clearskysec.com/wp-content/uploads/2014/09/8.png"
		$URL8 = "http://www.clearskysec.com/wp-content/uploads/2014/09/9.png"
		$Filename3 = "2.png"
		$Filename4 = "5.png"
		$Filename5 = "6.png"
		$Filename6 = "1.png"
		$Filename7 = "7.png"
		$Filename8 = "8.png"
		$Filename9 = "9.png"
	condition:
		$URL1 or $Host1 or $MD51 or $Filename1 or $MD52 or $IP1 or $Host2 or $IP2 or $Filename2 or $MD53 or $URL2 or $URL3 or $URL4 or $URL5 or $URL6 or $URL7 or $URL8 or $Filename3 or $Filename4 or $Filename5 or $Filename6 or $Filename7 or $Filename8 or $Filename9
}