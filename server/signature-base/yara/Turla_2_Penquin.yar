rule Turla_2_Penquin
{
	strings:
		$MD51 = "0994d9deb50352e76b0322f48ee576c6"
		$MD52 = "14ecd5e6fc8e501037b54ca263896a11"
		$IP1 = "80.248.65.183"
		$Host1 = "news-bbc.podzone.org"
		$Host2 = "bbc.podzone.org"
		$MD53 = "19fbd8cbfb12482e8020a887d6427315"
	condition:
		$MD51 or $MD52 or $IP1 or $Host1 or $Host2 or $MD53
}