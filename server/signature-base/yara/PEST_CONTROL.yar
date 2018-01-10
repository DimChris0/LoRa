rule PEST_CONTROL
{
	strings:
		$Host1 = "rpi.edu"
		$Host2 = "brown.edu"
		$Email1 = "denbos@rpi.edu"
		$Email2 = "jhertz@brown.edu"
		$IP1 = "172.16.1.1"
		$IP2 = "172.16.1.128"
		$Filepath1 = "C:\\DOCUME"
		$Filepath2 = "C:\\secret.txt"
		$IP3 = "172.16.250.128"
		$Host3 = "user.info"
		$MD51 = "a933d13f81649bebe035dc21f4002ff1"
		$MD52 = "202cb962ac59075b964b07152d234b70"
		$MD53 = "90dd3e7e19b35baa54015d0b4a08f2d0"
	condition:
		$Host1 or $Host2 or $Email1 or $Email2 or $IP1 or $IP2 or $Filepath1 or $Filepath2 or $IP3 or $Host3 or $MD51 or $MD52 or $MD53
}