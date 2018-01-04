rule Inception_APT_Analysis_Bluecoat
{
	strings:
		$CVE1 = "CVE-2012-0158"
		$MD51 = "4a4874fa5217a8523bf4d1954efb26ef"
		$Filename1 = "ntdll.dll"
		$Filename2 = "kernel32.dll"
		$Filename3 = "kernel32.dll"
		$Filename4 = "dropped.dll"
		$Filename5 = "wmiprvse.dll"
		$Filename6 = "wmiprvse.dll"
		$Filename7 = "wmiprvse.dll"
		$Host1 = "webdav.cloudme.com"
		$URL1 = "https://www.bluecoat.com/security-blog/2014-12-09/blue-coat-exposes-%E2%80%9C"
	condition:
		$CVE1 or $MD51 or $Filename1 or $Filename2 or $Filename3 or $Filename4 or $Filename5 or $Filename6 or $Filename7 or $Host1 or $URL1
}