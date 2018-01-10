rule CloudAtlas_RedOctober_APT
{
	strings:
		$Filename1 = "war.doc"
		$Filename2 = "Sale.doc"
		$Filename3 = "Rusia.doc"
		$CVE1 = "CVE-2012-0158"
		$Filename4 = "sale.doc"
		$Filename5 = "issues.doc"
		$Filename6 = "ctfmonrn.dll"
		$Filename7 = "bicorporate.dll"
		$Filename8 = "fundamentive.dll"
		$Filename9 = "papersaving.dll"
		$Filename10 = "previliges.dll"
		$Filename11 = "steinheimman.dll"
		$MD51 = "E211C2BAD9A83A6A4247EC3959E2A730"
		$MD52 = "DECF56296C50BD3AE10A49747573A346"
		$MD53 = "D171DB37EF28F42740644F4028BCF727"
		$MD54 = "f4e15c1c2c95c651423dbb4cbe6c8fd5"
		$MD55 = "649ff144aea6796679f8f9a1e9f51479"
		$MD56 = "40e70f7f5d9cb1a669f8d8f306113485"
		$MD57 = "58db8f33a9cdd321d9525d1e68c06456"
		$MD58 = "f5476728deb53fe2fa98e6a33577a9da"
		$Host1 = "cloudme.com"
		$Host2 = "mydrive.ch"
		$Host3 = "-2012-0158.eu"
		$Host4 = "-2012-0158.aw"
	condition:
		$Filename1 or $Filename2 or $Filename3 or $CVE1 or $Filename4 or $Filename5 or $Filename6 or $Filename7 or $Filename8 or $Filename9 or $Filename10 or $Filename11 or $MD51 or $MD52 or $MD53 or $MD54 or $MD55 or $MD56 or $MD57 or $MD58 or $Host1 or $Host2 or $Host3 or $Host4
}