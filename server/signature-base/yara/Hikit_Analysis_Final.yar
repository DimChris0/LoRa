rule Hikit_Analysis_Final
{
	strings:
		$Filepath1 = "H:\\JmVodServer\\Matrix_new2"
		$Filepath2 = "E:\\SourceCode\\Matrix_new"
		$URL1 = "http://en.pudn.com/downloads74/sourcecode/windows/vxd/detail265112_en.html"
		$URL2 = "http://forum.eviloctal.com/archiver/tid"
		$Filename1 = "detail265112_en.html"
		$Filename2 = "29604.html"
		$Host1 = "en.pudn.com"
		$Host2 = "forum.eviloctal.com"
		$Filename3 = "services.exe"
		$URL3 = "http://www.ndis.com/ndis"
		$Filename4 = "programinstall.htm"
		$Host3 = "www.ndis.com"
		$URL4 = "http://www.oberhumer.com/opensource/lzo"
		$Host4 = "www.oberhumer.com"
		$SHA11 = "b04de6c417b6f8836e3f2d8822be2e68f4f9722b"
		$SHA12 = "7c4da9deff3e5c7611b9e1bd67d0e74aa7d2d0f6"
		$Filename5 = "w7fw.sys"
	condition:
		$Filepath1 or $Filepath2 or $URL1 or $URL2 or $Filename1 or $Filename2 or $Host1 or $Host2 or $Filename3 or $URL3 or $Filename4 or $Host3 or $URL4 or $Host4 or $SHA11 or $SHA12 or $Filename5
}