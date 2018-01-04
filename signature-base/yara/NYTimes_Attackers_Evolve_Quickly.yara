rule NYTimes_Attackers_Evolve_Quickly
{
	strings:
		$Filename1 = "myScript.js"
		$Host1 = "status.acmetoy.com"
		$Host2 = "status.acmetoy.com"
		$MD51 = "832f5e01be536da71d5b3f7e41938cfb"
		$MD52 = "832f5e01be536da71d5b3f7e41938cfb"
		$MD53 = "cb3dcde34fd9ff0e19381d99b02f9692"
		$MD54 = "cb3dcde34fd9ff0e19381d99b02f9692"
		$MD55 = "aa873ed803ca800ce92a39d9a683c644"
		$URL1 = "http://www.nytimes.com/2013/01/31/technology/chinese-hackers-infiltrate-new-york-times"
		$Filename2 = "computers.html"
		$Filename3 = "wp_ixeshe.pdf"
	condition:
		$Filename1 or $Host1 or $Host2 or $MD51 or $MD52 or $MD53 or $MD54 or $MD55 or $URL1 or $Filename2 or $Filename3
}