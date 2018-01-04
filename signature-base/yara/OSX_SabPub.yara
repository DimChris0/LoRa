rule OSX_SabPub
{
	strings:
		$Host1 = "onedumb.com"
		$Filename1 = "8958.doc"
		$Host2 = "onedumb.com"
		$Host3 = "onedumb.com"
		$CVE1 = "CVE-2009-0563"
		$MD51 = "40C8786A4887A763D8F3E5243724D1C9"
		$CVE2 = "CVE-2009-0563"
	condition:
		$Host1 or $Filename1 or $Host2 or $Host3 or $CVE1 or $MD51 or $CVE2
}