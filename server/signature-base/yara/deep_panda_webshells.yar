rule deep_panda_webshells
{
	strings:
		$Filepath1 = "E:\\inetpub\\wwwroot"
		$MD51 = "ffa82c64720179878b25793f17b304d7"
		$URL1 = "http://<webserver>/showimage.asp*=%52%65%73%70%6F"
		$Filepath2 = "C:\\inetpub\\wwwroot\\aspnet_client\\system_web"
		$MD52 = "cc875db104a602e6c12196fe90559fb6"
	condition:
		$Filepath1 or $MD51 or $URL1 or $Filepath2 or $MD52
}rule deep_panda_webshells
{
	strings:
		$Filepath1 = "E:\\inetpub\\wwwroot"
		$MD51 = "ffa82c64720179878b25793f17b304d7"
		$URL1 = "http://<webserver>/showimage.asp*=%52%65%73%70%6F"
		$Filepath2 = "C:\\inetpub\\wwwroot\\aspnet_client\\system_web"
		$MD52 = "cc875db104a602e6c12196fe90559fb6"
	condition:
		$Filepath1 or $MD51 or $URL1 or $Filepath2 or $MD52
}