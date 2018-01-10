rule Duqu_Trojan_Questions_and_Answers
{
	strings:
		$IP1 = "206.183.111.97"
		$Host1 = "kasperskychk.dyndns.org"
		$Filename1 = "jminet7.sys"
		$Filename2 = "cmi4432.sys"
		$Filename3 = "keylogger.exe"
		$Filename4 = "nfred965.sys"
		$Filename5 = "nred961.sys"
		$Filename6 = "adpu321.sys"
		$Filename7 = "iaStor451.sys"
		$MD51 = "0eecd17c6c215b358b7b872b74bfd800"
		$MD52 = "b4ac366e24204d821376653279cbad86"
		$MD53 = "94c4ef91dfcd0c53a96fdc387f9f9c35"
		$MD54 = "4541e850a228eb69fd0f0e924624b245"
		$MD55 = "0a566b1616c8afeef214372b1a0580c7"
		$MD56 = "e8d6b4dadb96ddb58775e6c85b10b6cc"
		$MD57 = "9749d38ae9b9ddd81b50aad679ee87ec"
		$MD58 = "c9a31ea148232b201fe7cb7db5c75f5e"
		$MD59 = "f60968908f03372d586e71d87fe795cd"
		$MD510 = "3d83b077d32c422d6c7016b5083b9fc2"
		$MD511 = "bdb562994724a35a1ec5b9e85b8e054f"
	condition:
		$IP1 or $Host1 or $Filename1 or $Filename2 or $Filename3 or $Filename4 or $Filename5 or $Filename6 or $Filename7 or $MD51 or $MD52 or $MD53 or $MD54 or $MD55 or $MD56 or $MD57 or $MD58 or $MD59 or $MD510 or $MD511
}