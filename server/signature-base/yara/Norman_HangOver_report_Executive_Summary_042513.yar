rule Norman_HangOver_report_Executive_Summary_042513
{
	strings:
		$Host1 = "claritycommunications.us"
		$Email1 = "norman@claritycommunications.us"
	condition:
		$Host1 or $Email1
}