rule DTL__
{
	strings:
		$CVE1 = "CVE-2014-6332"
		$Filename1 = "plug.exe"
		$Filename2 = "z1.exe"
		$Filename3 = "clbcatq.dll"
		$Filename4 = "profapi.dll"
		$Filename5 = "wuauclt.exe"
		$Registry1 = "HKCU\\Software\\Microsoft\\Windows\\Current"
		$Filename6 = "clbcaiq.dll"
		$MD51 = "a6a18c846e5179259eba9de238f67e41"
		$MD52 = "ad17eff26994df824be36db246c8fb6a"
		$MD53 = "55f84d88d84c221437cd23cdbc541d2e"
		$IP1 = "45.64.74.101"
		$IP2 = "103.229.127.104"
		$MD54 = "ec532bbe9d0882d403473102e9724557"
		$Host1 = "aoemvp.com"
		$Email1 = "lim.kiu@hotmail.com"
		$MD55 = "279ef79f904476ba0f9f44c87358bb1f"
		$MD56 = "42b76c0503a6bf21f1ea86e0b14d67ea"
		$MD57 = "cff25fe24a90ef63eaa168c07008c2bb"
		$MD58 = "f66b64ef984ac46ac7395358059979bc"
		$MD59 = "efd9dc39682312d6576468f5c0eb6236"
		$URL1 = "http://dragonthreat.blogspot.hk"
		$Host2 = "dragonthreat.blogspot.hk"
		$Email2 = "dragonthreatlabs@gmail.com"
	condition:
		$CVE1 or $Filename1 or $Filename2 or $Filename3 or $Filename4 or $Filename5 or $Registry1 or $Filename6 or $MD51 or $MD52 or $MD53 or $IP1 or $IP2 or $MD54 or $Host1 or $Email1 or $MD55 or $MD56 or $MD57 or $MD58 or $MD59 or $URL1 or $Host2 or $Email2
}