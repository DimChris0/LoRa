rule Scarab_Russian
{
	strings:
		$Filename1 = "doc.scr"
		$Filename2 = "year.doc"
		$Filename3 = "seclog32.dll"
	condition:
		$Filename1 or $Filename2 or $Filename3
}