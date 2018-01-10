rule FireEye_Terminator_RAT
{
	strings:
		$Filename1 = "103.doc"
		$Filename2 = "DW20.exe"
		$Filename3 = "svchost_.exe"
		$Filename4 = "sss.exe"
		$CVE1 = "CVE-2012-0158"
		$MD51 = "a130b2e578d82409021b3c9ceda657b7"
		$MD52 = "7B18E1F0CE0CB7EEA990859EF6DB810C"
		$MD53 = "93F51B957DA86BDE1B82934E73B10D9D"
		$IP1 = "6.0.1.3"
		$Host1 = "liumingzhen.zapto.org"
		$Host2 = "liumingzhen.myftp.org"
		$IP2 = "123.51.208.69"
		$MD54 = "50d5e73ff8a0693ed2ee2d320af3b304"
		$IP3 = "123.51.208.142"
		$Host3 = "catlovers.25u.com"
		$MD55 = "bfc96694731f3cf39bcad6e0716c5746"
		$MD56 = "01da7213940a74c292d09ebe17f1bd01"
	condition:
		$Filename1 or $Filename2 or $Filename3 or $Filename4 or $CVE1 or $MD51 or $MD52 or $MD53 or $IP1 or $Host1 or $Host2 or $IP2 or $MD54 or $IP3 or $Host3 or $MD55 or $MD56
}