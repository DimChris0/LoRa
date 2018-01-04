rule Chinese_MITM_Google
{
	strings:
		$Host1 = "google.com.hk"
		$Host2 = "4or6.com"
		$Host3 = "pku-bj-v6.cernet2.net"
		$Host4 = "cernet2.net"
		$SHA11 = "f6beadb9bc02e0a152d71c318739cdecfc1c085d"
		$URL1 = "http://netresec.com/?b=14955CB"
		$Host5 = "netresec.com"
	condition:
		$Host1 or $Host2 or $Host3 or $Host4 or $SHA11 or $URL1 or $Host5
}