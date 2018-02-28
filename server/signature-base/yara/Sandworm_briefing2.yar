rule Sandworm_briefing2
{
	strings:
		$CVE1 = "CVE-2014-4114"
		$CVE2 = "CVE-2013-3906"
	condition:
		$CVE1 or $CVE2
}