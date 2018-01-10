rule ANALYSIS_ON_APT_TO_BE_ATTACK_THAT_FOCUSING_ON_CHINAS_GOVERNMENT_AGENCY_
{
	strings:
		$Filename1 = "powershell.exe"
		$Filename2 = "ab.exe"
		$MD51 = "44BCF2DD262F12222ADEAB6F59B2975B"
		$URL1 = "http://146.0.43.107/hfYn"
		$IP1 = "146.0.43.107"
		$Filename3 = "rundll32.exe"
		$Host1 = "69.info"
		$Host2 = "build.sh"
		$URL2 = "https://plus.google.com/116899857642591292745/posts"
		$URL3 = "https://github.com/rsmudge"
		$URL4 = "https://www.youtube.com/channel/UCJU2r634VNPeCRug7Y7qdcw"
		$URL5 = "http://www.oldschoolirc.com"
		$URL6 = "https://twitter.com/rsmudge"
		$URL7 = "http://www.hick.org/~raffi/index.html"
		$URL8 = "http://www.blackhat.com/html/bh-us-12/speakers/Raphael-Mudge.html"
		$Filename4 = "index.html"
		$Filename5 = "Raphael-Mudge.html"
		$Host3 = "www.oldschoolirc.com"
		$Host4 = "www.hick.org"
		$Host5 = "www.blackhat.com"
		$URL9 = "http://www.linkedin.com/in/rsmudge"
		$Host6 = "www.antiy.com"
		$Host7 = "www.antiy.cn"
		$Host8 = "www.antiy.net"
	condition:
		$Filename1 or $Filename2 or $MD51 or $URL1 or $IP1 or $Filename3 or $Host1 or $Host2 or $URL2 or $URL3 or $URL4 or $URL5 or $URL6 or $URL7 or $URL8 or $Filename4 or $Filename5 or $Host3 or $Host4 or $Host5 or $URL9 or $Host6 or $Host7 or $Host8
}