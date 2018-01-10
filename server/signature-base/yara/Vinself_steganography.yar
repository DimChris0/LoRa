rule Vinself_steganography
{
	strings:
		$IP1 = "2.2.2.2"
		$IP2 = "3.3.3.3"
		$IP3 = "4.4.4.4"
	condition:
		$IP1 or $IP2 or $IP3
}