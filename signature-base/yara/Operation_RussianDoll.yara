rule Operation_RussianDoll
{
	strings:
		$IP1 = "17.0.0.134"
		$Host1 = "icloud.com"
	condition:
		$IP1 or $Host1
}