rule OperationCleaver_The_Notepad_Files
{
	strings:
		$Filename1 = "notepad.exe"
		$Filename2 = "Notepad3.exe"
		$Filename3 = "Notepad4.exe"
		$MD51 = "83868cdff62829fe3b897e2720204679"
		$MD52 = "bfc59f1f442686af73704eff6c0226f0"
		$MD53 = "e8ea10d5cde2e8661e9512fb684c4c98"
		$MD54 = "baa76a571329cdc4d7e98c398d80450c"
		$Filename4 = "notepad10.exe"
		$MD55 = "19d9b37d3acf3468887a4d41bf70e9aa"
		$MD56 = "d378bffb70923139d6a4f546864aa61c"
		$IP1 = "108.175.152.230"
	condition:
		$Filename1 or $Filename2 or $Filename3 or $MD51 or $MD52 or $MD53 or $MD54 or $Filename4 or $MD55 or $MD56 or $IP1
}