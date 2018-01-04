rule Miniduke_twitter
{
	strings:
		$CVE1 = "CVE-2014-1761"
		$Filename1 = "kernel32.dll"
		$Filename2 = "rundll32.exe"
		$Filepath1 = "C:\\Windows\\system32\\rundll32.exe"
		$Filepath2 = "C:\\Windows\\system32\\rundll32.exe"
		$Filepath3 = "C:\\DOCUME"
		$Filename3 = "rundll32.exe"
		$Filename4 = "rundll32.exe"
		$Filename5 = "rundll32.exe"
		$Host1 = "data.cat"
		$URL1 = "http://www.geoiptool.com"
		$Host2 = "www.geoiptool.com"
		$Filename6 = "cryptdll.dll"
		$SHA11 = "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"
		$SHA12 = "a94a8fe5dce4f01c1c4c0873d391e987982fbbd3"
		$SHA13 = "58be4918df7fbf1e12de1a31d4f622e570a81b93"
		$CVE2 = "CVE-2014-1761"
		$CVE3 = "CVE-2014-1761"
		$SHA14 = "b27f6174173e71dc154413a525baddf3d6dea1fd"
		$SHA15 = "c059303cd420dc892421ba4465f09b892de93c77"
		$URL2 = "https://github.com/eset/malware-research/tree/master/miniduke"
	condition:
		$CVE1 or $Filename1 or $Filename2 or $Filepath1 or $Filepath2 or $Filepath3 or $Filename3 or $Filename4 or $Filename5 or $Host1 or $URL1 or $Host2 or $Filename6 or $SHA11 or $SHA12 or $SHA13 or $CVE2 or $CVE3 or $SHA14 or $SHA15 or $URL2
}