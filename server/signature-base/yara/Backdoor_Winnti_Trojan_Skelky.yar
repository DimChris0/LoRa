rule Backdoor_Winnti_Trojan_Skelky
{
	strings:
		$Filename1 = "msuta64.dll"
		$Filename2 = "ole64.dll"
		$Filename3 = "HookDC64.dll"
		$Filename4 = "HookDC.dll"
		$Filename5 = "olex64.dll"
		$Filename6 = "ole.dll"
		$Filename7 = "jqs.exe"
		$MD51 = "66da7ed621149975f6e643b4f9886cfd"
		$MD52 = "bf45086e6334f647fda33576e2a05826"
		$MD53 = "a487f1668390df0f4951b7292bae6ecf"
		$MD54 = "8ba4df29b0593be172ff5678d8a05bb3"
		$MD55 = "f01026e1107b722435126c53b2af47a9"
		$MD56 = "747cc5ce7f2d062ebec6219384b57e8c"
		$MD57 = "600b604784594e3339776c6563aa45a1"
		$MD58 = "48377c1c4cfedebe35733e9c3675f9be"
	condition:
		$Filename1 or $Filename2 or $Filename3 or $Filename4 or $Filename5 or $Filename6 or $Filename7 or $MD51 or $MD52 or $MD53 or $MD54 or $MD55 or $MD56 or $MD57 or $MD58
}