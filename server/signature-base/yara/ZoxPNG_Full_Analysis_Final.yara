rule ZoxPNG_Full_Analysis_Final
{
	strings:
		$URL1 = "http://{C2Address}&docid=1bi0Ti1ZVr4bEM&imgurl=http"
		$URL2 = "http://127.0.0.1&docid=1bi0Ti1ZVr4bEM&imgurl=http"
		$Filename1 = "20141020021012.png"
		$Filename2 = "cmd.exe"
		$Filename3 = "cmd.exe"
		$SHA11 = "60415999bc82dc9c8f4425f90e41a98d514f76a2"
		$SHA12 = "40f9cde4ccd1b1b17a647c6fc72c5c5cd40d2b08"
		$SHA13 = "7dd556415487cc192b647c9a7fde70896eeee7a2"
		$SHA14 = "40f9cde4ccd1b1b17a647c6fc72c5c5cd40d2b08"
		$SHA15 = "60415999bc82dc9c8f4425f90e41a98d514f76a2"
		$SHA16 = "40f9cde4ccd1b1b17a647c6fc72c5c5cd40d2b08"
		$SHA17 = "60415999bc82dc9c8f4425f90e41a98d514f76a2"
		$Filename4 = "cmd.exe"
		$Host1 = "www.4nb.co.kr"
		$SHA18 = "40f9cde4ccd1b1b17a647c6fc72c5c5cd40d2b08"
		$SHA19 = "60415999bc82dc9c8f4425f90e41a98d514f76a2"
		$SHA110 = "b51e419bf999332e695501c62c5b4aee5b070219"
		$URL3 = "http://www.pudn.com/downloads183/sourcecode/hack/exploit/detail861817.html"
		$URL4 = "http://www.exploit-db.com/download/21371"
		$Filename5 = "detail861817.html"
		$Host2 = "www.pudn.com"
	condition:
		$URL1 or $URL2 or $Filename1 or $Filename2 or $Filename3 or $SHA11 or $SHA12 or $SHA13 or $SHA14 or $SHA15 or $SHA16 or $SHA17 or $Filename4 or $Host1 or $SHA18 or $SHA19 or $SHA110 or $URL3 or $URL4 or $Filename5 or $Host2
}