rule TrapX_ZOMBIE_Report_Final
{
	strings:
		$Host1 = "www.trapx.com"
		$Host2 = "trapx.com"
		$Email1 = "info@trapx.com"
		$Host3 = "www.trapx.com"
		$Host4 = "trapx.com"
		$Email2 = "info@trapx.com"
		$Host5 = "www.trapx.com"
		$Host6 = "trapx.com"
		$Email3 = "info@trapx.com"
	condition:
		$Host1 or $Host2 or $Email1 or $Host3 or $Host4 or $Email2 or $Host5 or $Host6 or $Email3
}