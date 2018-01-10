rule UnFINished_Business_pwd
{
	strings:
		$MD51 = "d102693540b53f9a564e3a550f938709"
		$Filename1 = "WINWORD32.exe"
		$URL1 = "http://www.advantarlabs.com/plugins/extension-­xtd/WINWORD32.exe"
		$URL2 = "http://www.reuters.com/article/2015/06/23/us-hackers-insidertrading-idUSKBN0P31M720150623"
		$URL3 = "https://www2.fireeye.com/rs/fireye/images/rpt-fin4.pdf"
		$Filename2 = "rpt-fin4.pdf"
		$Host1 = "www.advantarlabs.com"
		$URL4 = "https://www.esentire.com/wp-content/uploads/2013/11/esentire_alert_20131108_DOCM.pdf"
		$Filename3 = "esentire_alert_20131108_DOCM.pdf"
		$Host2 = "www.esentire.com"
	condition:
		$MD51 or $Filename1 or $URL1 or $URL2 or $URL3 or $Filename2 or $Host1 or $URL4 or $Filename3 or $Host2
}