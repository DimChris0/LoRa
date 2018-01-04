rule Group_72
{
	strings:
		$CVE1 = "CVE-2014-0322"
		$CVE2 = "CVE-2012-4792"
		$Host1 = "companyname.attackerdomain.com"
		$Host2 = "companyacronym.attackerdomain.com"
		$CVE3 = "CVE-2012-1889"
		$CVE4 = "CVE-2013-3893"
	condition:
		$CVE1 or $CVE2 or $Host1 or $Host2 or $CVE3 or $CVE4
}