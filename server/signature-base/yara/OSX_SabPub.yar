rule OSX_SabPub
{
	strings:
		$Host1 = "onedumb.com"
		$Filename1 = "8958.doc"
		$CVE1 = "CVE-2009-0563"
		$MD51 = "40C8786A4887A763D8F3E5243724D1C9"
	condition:
		$Host1 or $Filename1 or $CVE1 or $MD51
}