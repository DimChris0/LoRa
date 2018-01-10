rule oil_tanker_en
{
	strings:
		$Host1 = "pandasecurity.com"
		$Filename1 = "deca.bat"
		$Filename2 = "pic.pdf"
		$Filename3 = "dcp.exe"
		$Filename4 = "unzip2.exe"
		$Filename5 = "bare.zip"
		$Filename6 = "unzip.exe"
		$Filename7 = "bar.zip"
		$Filename8 = "ici.bat"
		$Filename9 = "aagi.bat"
		$Filename10 = "iei.bat"
		$Filename11 = "iewi.bat"
		$Filename12 = "image.exe"
		$Filename13 = "images.exe"
		$Filename14 = "viewer.exe"
		$Filename15 = "mdei.exe"
	condition:
		$Host1 or $Filename1 or $Filename2 or $Filename3 or $Filename4 or $Filename5 or $Filename6 or $Filename7 or $Filename8 or $Filename9 or $Filename10 or $Filename11 or $Filename12 or $Filename13 or $Filename14 or $Filename15
}