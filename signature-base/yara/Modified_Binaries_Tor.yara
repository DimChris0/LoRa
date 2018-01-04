rule Modified_Binaries_Tor
{
	strings:
		$SHA11 = "8361A794DFA231D863E109FC9EEEF21F4CF09DDD"
		$URL1 = "https://check.torproject.org/exit-addresses"
		$IP1 = "78.24.222.229"
		$Host1 = "check.torproject.org"
	condition:
		$SHA11 or $URL1 or $IP1 or $Host1
}