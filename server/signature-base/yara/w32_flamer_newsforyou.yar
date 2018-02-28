rule w32_flamer_newsforyou
{
	strings:
		$Host1 = "dnslocation.info"
		$MD51 = "59c5452fb2ba21091513ccdc1e0ec7fd"
		$MD52 = "27934e96d90d06818674b98bec7230fa"
		$IP1 = "1.4.11.4"
	condition:
		$Host1 or $MD51 or $MD52 or $IP1
}