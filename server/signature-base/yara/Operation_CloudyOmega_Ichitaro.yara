rule Operation_CloudyOmega_Ichitaro
{
	strings:
		$CVE1 = "CVE-2012-5054"
		$CVE2 = "CVE-2013-0634"
		$CVE3 = "CVE-2013-0634"
	condition:
		$CVE1 or $CVE2 or $CVE3
}