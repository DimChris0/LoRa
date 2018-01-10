rule TrapX_ZOMBIE_Report_Final
{
	strings:
		$Host1 = "www.trapx.com"
		$Host2 = "trapx.com"
		$Email1 = "info@trapx.com"
	condition:
		$Host1 or $Host2 or $Email1
}