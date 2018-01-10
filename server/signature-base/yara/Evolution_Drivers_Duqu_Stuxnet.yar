rule Evolution_Drivers_Duqu_Stuxnet
{
	strings:
		$Filename1 = "Mrxcls.sys"
		$Filename2 = "Mrxnet.sys"
		$Filename3 = "Jmidebs.sys"
		$Filename4 = "mrxcls.sys"
		$Filename5 = "mrxnet.sys"
		$Filename6 = "jmidebs.sys"
		$Filename7 = "rtniczw.sys"
		$MD51 = "546C4BBEBF02A1604EB2CAAAD4974DE0"
		$Filename8 = "rndismpc.sys"
		$MD52 = "9AEC6E10C5EE9C05BED93221544C783E"
	condition:
		$Filename1 or $Filename2 or $Filename3 or $Filename4 or $Filename5 or $Filename6 or $Filename7 or $MD51 or $Filename8 or $MD52
}