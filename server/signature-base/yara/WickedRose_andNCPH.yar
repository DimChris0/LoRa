rule WickedRose_andNCPH
{
	strings:
		$URL1 = "http://www.study-in-china.org/school/Sichuan/suse"
		$Host1 = "www.suse.edu.cn"
		$Host2 = "www.study-in-china.org"
		$Filename1 = "5-16-2006.doc"
		$Filename2 = "winguis.dll"
		$Host3 = "nease.net"
		$URL2 = "http://rodag.blogbus.com/index.html"
		$Filename3 = "index.html"
		$Host4 = "rodag.blogbus.com"
		$Host5 = "enjoy.irdet.com"
		$Host6 = "enjoy.bmwsee.com"
		$Host7 = "windowsupdates.net"
		$Host8 = "www.mghacker.com"
		$URL3 = "http://rodag.blogbus.com"
		$URL4 = "http://www.cppblog.com/charles"
		$URL5 = "http://kungbim.blogbus.com"
		$Host9 = "www.cppblog.com"
		$Host10 = "kungbim.blogbus.com"
		$Host11 = "www.ncph.net"
		$Host12 = "ncph.net"
		$Host13 = "126.com"
		$Email1 = "ncph2005@126.com"
		$Host14 = "163.com"
		$Host15 = "cnasm.com"
		$Host16 = "tthacker.cublog.cn"
		$Email2 = "whg@163.com"
	condition:
		$URL1 or $Host1 or $Host2 or $Filename1 or $Filename2 or $Host3 or $URL2 or $Filename3 or $Host4 or $Host5 or $Host6 or $Host7 or $Host8 or $URL3 or $URL4 or $URL5 or $Host9 or $Host10 or $Host11 or $Host12 or $Host13 or $Email1 or $Host14 or $Host15 or $Host16 or $Email2
}