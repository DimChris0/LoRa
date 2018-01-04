rule Op_Clandestine_Fox
{
	strings:
		$CVE1 = "CVE-2014-1776"
		$CVE2 = "CVE-2010-3962"
	condition:
		$CVE1 or $CVE2
}