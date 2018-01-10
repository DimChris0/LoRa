rule FTA__Follow_UP
{
	strings:
		$Filename1 = "netsat.exe"
		$Filename2 = "netui3.dll"
		$Filename3 = "Netsat.exe"
		$Filename4 = "setup35.exe"
		$Filename5 = "update.exe"
		$Filename6 = "winmgt.dll"
		$MD51 = "68aed7b1f171b928913780d5b21f7617"
		$MD52 = "eb8399483b55f416e48a320d68597d72"
		$Filepath1 = "E:\\RECYCLED\\RECYCLED\\SYS\\file1.txt"
		$Filepath2 = "E:\\RECYCLED\\RECYCLED\\SYS\\interesting.txt"
		$Filename7 = "netu3.dll"
	condition:
		$Filename1 or $Filename2 or $Filename3 or $Filename4 or $Filename5 or $Filename6 or $MD51 or $MD52 or $Filepath1 or $Filepath2 or $Filename7
}