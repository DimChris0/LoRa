rule Forkmeiamfamous_SeaDuke
{
	strings:
		$Filepath1 = "C:\\Projects\\nemesis-gemina\\nemesis\\bin\\carriers\\ezlzma_x86_exe.pdb"
	condition:
		$Filepath1
}