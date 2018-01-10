rule US__Yarochkin_In_Depth_Analysis_of_Escalated_APT_Attacks_Slides
{
	strings:
		$Filename1 = "31805794.html"
		$Host1 = "blog.yam.com"
		$Host2 = "diary.blog.yam.com"
		$Host3 = "blogs.yahoo.co.jp"
		$Host4 = "www.plurk.com"
		$Host5 = "lab.com"
		$Host6 = "xecure-lab.com"
		$Host7 = "hitcon.org"
		$Host8 = "plurk.com"
		$Email1 = "benson.wu@xecure-lab.com"
		$Email2 = "jeremy.chiu@xecure-lab.com"
		$Email3 = "pk@hitcon.org"
	condition:
		$Filename1 or $Host1 or $Host2 or $Host3 or $Host4 or $Host5 or $Host6 or $Host7 or $Host8 or $Email1 or $Email2 or $Email3
}