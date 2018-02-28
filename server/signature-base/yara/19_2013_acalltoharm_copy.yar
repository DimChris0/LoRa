rule _2013_acalltoharm
{
	strings:
		$URL1 = "http://www.mediafire.com/download/[REDACTED]/VPN-Pro.zip"
	condition:
		$URL1
}
