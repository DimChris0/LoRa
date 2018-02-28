rule duqu2_crysys
{
	strings:
		$MD51 = "c7c647a14cb1b8bc141b089775130834"
		$MD52 = "3f52ea949f2bd98f1e6ee4ea1320e80d"
		$IP1 = "1.9.2.9"
		$IP2 = "11.0.696.57"
		$IP3 = "16.0.912.77"
		$IP4 = "17.0.963.66"
		$IP5 = "17.0.963.56"
		$IP6 = "5.0.1.6"
		$IP7 = "1.9.1.16"
		$Host1 = "gpl3.selfsigned.org"
		$URL1 = "http://www.crysys.hu/publications/files/bencsathPBF11duqu.pdf"
		$URL2 = "http://www.kaspersky.com/about/press/major_malware_outbreaks/duqu"
		$Filename1 = "bencsathPBF11duqu.pdf"
		$Filename2 = "w32_duqu_the_precursor_to_the_next_stuxnet.pdf"
		$Filename3 = "w32_stuxnet_dossier.pdf"
		$Email1 = "bencsath@crysys.hu"
		$Email2 = "boldi@crysys.hu"
	condition:
		$MD51 or $MD52 or $IP1 or $IP2 or $IP3 or $IP4 or $IP5 or $IP6 or $IP7 or $Host1 or $URL1 or $URL2 or $Filename1 or $Filename2 or $Filename3 or $Email1 or $Email2
}