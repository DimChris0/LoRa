rule Sandworm_briefing2
{
	strings:
		$CVE1 = "CVE-2014-4114"
		$CVE2 = "CVE-2013-3906"
		$CVE3 = "CVE-2014-4114"
		$CVE4 = "CVE-2013-3906"
		$CVE5 = "CVE-2014-4114"
	condition:
		$CVE1 or $CVE2 or $CVE3 or $CVE4 or $CVE5
}