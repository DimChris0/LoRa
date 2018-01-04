rule how_can_u_tell_Aurora
{
	strings:
		$Filename1 = "Rasmon.dll"
		$Filename2 = "a.exe"
		$Filename3 = "b.exe"
		$Filename4 = "AppMgmt.dll"
		$Filename5 = "A0029670.dll"
		$Filename6 = "msconfig32.sys"
		$Filename7 = "VedioDriver.dll"
		$Filename8 = "acelpvc.dll"
		$Filename9 = "Roarur.dll"
		$Filename10 = "securmon.dll"
		$MD51 = "0F9C5408335833E72FE73E6166B5A01B"
		$MD52 = "CD36A3071A315C3BE6AC3366D80BB59C"
		$MD53 = "9F880AC607CBD7CDFFFA609C5883C708"
		$MD54 = "6A89FBE7B0D526E3D97B0DA8418BF851"
		$MD55 = "3A33013A47C5DD8D1B92A4CFDCDA3765"
		$MD56 = "7A62295F70642FEDF0D5A5637FEB7986"
		$MD57 = "467EEF090DEB3517F05A48310FCFD4EE"
		$MD58 = "4A47404FC21FFF4A1BC492F9CD23139C"
		$MD59 = "E3798C71D25816611A4CAB031AE3C27A"
	condition:
		$Filename1 or $Filename2 or $Filename3 or $Filename4 or $Filename5 or $Filename6 or $Filename7 or $Filename8 or $Filename9 or $Filename10 or $MD51 or $MD52 or $MD53 or $MD54 or $MD55 or $MD56 or $MD57 or $MD58 or $MD59
}