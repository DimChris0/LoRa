rule OrcaRAT
{
	strings:
		$SHA2561 = "253a704acd7952677c70e0c2d787791b8359efe2c92a5e77acea028393a85613"
		$SHA2562 = "253a704acd7952677c70e0c2d787791b8359efe2c92a5e77acea028393a85613"
		$Host1 = "vnd.ms"
		$IP1 = "11.38.64.251"
		$IP2 = "123.120.115.77"
		$IP3 = "123.120.99.228"
		$IP4 = "142.0.134.20"
		$IP5 = "147.96.68.184"
		$IP6 = "176.31.24.182"
		$IP7 = "176.31.24.184"
		$IP8 = "190.114.241.170"
		$IP9 = "200.78.201.24"
		$IP10 = "202.124.151.94"
		$IP11 = "202.2.108.142"
		$IP12 = "203.146.251.11"
		$IP13 = "204.152.209.74"
		$IP14 = "213.147.54.170"
		$IP15 = "23.19.39.19"
		$IP16 = "58.71.158.21"
		$IP17 = "62.73.174.134"
		$IP18 = "71.183.67.163"
		$IP19 = "74.116.128.15"
		$Host2 = "adda.lengendport.com"
		$Host3 = "tsl.gettrials.com"
		$Host4 = "auty.organiccrap.com"
		$MD51 = "07b40312047f204a2c1fbd94fba6f53b"
		$MD52 = "f6456b115e325b612e0d144c8090720f"
		$MD53 = "139b8e1b665bb9237ec51ec4bef22f58"
		$IP20 = "81.218.149.207"
		$IP21 = "91.198.50.31"
		$Host5 = "adda.lengendport.com"
		$Host6 = "affisensors.com"
		$Host7 = "analysis.ittecbbs.com"
		$Host8 = "at.acmetoy.com"
		$Host9 = "aucy.affisensors.com"
		$Host10 = "auty.organiccrap.com"
		$Host11 = "bbs.dynssl.com"
		$Host12 = "bbs.serveuser.com"
		$Host13 = "bbslab.acmetoy.com"
		$Host14 = "bbslab.lflink.com"
		$Host15 = "cdna.acmetoy.com"
		$Host16 = "cune.lengendport.com"
		$Host17 = "cure.yourtrap.com"
		$Host18 = "dasheng.lonidc.com"
		$Host19 = "dns.affisensors.com"
		$Host20 = "edu.authorizeddns.org"
		$Host21 = "edu.onmypc.org"
		$Host22 = "ftp.bbs.dynssl.com"
		$Host23 = "ftp.bbs.serveuser.com"
		$Host24 = "ftp.bbslab.acmetoy.com"
		$Host25 = "ftp.edu.authorizeddns.org"
		$Host26 = "ftp.edu.onmypc.org"
		$Host27 = "ftp.lucy.justdied.com"
		$Host28 = "ftp.nuac.jkub.com"
		$Host29 = "ftp.osk.lflink.com"
		$Host30 = "ftp.reg.dsmtp.com"
		$Host31 = "ftp.tt0320.portrelay.com"
		$Host32 = "home.affisensors.com"
		$Host33 = "hot.mrface.com"
		$Host34 = "info.affisensors.com"
		$Host35 = "jucy.wikaba.com"
		$Host36 = "jutty.organiccrap.com"
		$Host37 = "lengendport.com"
		$Host38 = "lucy.justdied.com"
		$Host39 = "newtect.ddns.us"
		$MD54 = "84c68f2d2dd569c4620dabcecd477e69"
		$MD55 = "8fbc8c7d62a41b6513603c4051a3ee7b"
		$MD56 = "fee0e6b8157099ad09380a94b7cbbea4"
		$URL1 = "http://intelreport.mandiant.com/Mandiant_APT1_Report.pdf"
		$URL2 = "http://www.lockheedmartin.com/content/dam/lockheed/data/corporate/documents/LM-White"
		$Filename1 = "Mandiant_APT1_Report.pdf"
		$Filename2 = "Paper-Intel-Driven-Defense.pdf"
		$Host40 = "nuac.jkub.com"
		$Host41 = "nunok.ninth.biz"
		$Host42 = "osk.lflink.com"
		$Host43 = "philipine.gnway.net"
		$Host44 = "pure.mypop3.org"
		$Host45 = "reg.dsmtp.com"
		$Host46 = "tt0320.portrelay.com"
		$Host47 = "venus.gr8domain.biz"
		$Host48 = "www.bbs.dynssl.com"
		$Host49 = "www.bbs.serveuser.com"
		$Host50 = "www.bbslab.acmetoy.com"
		$Host51 = "www.edu.authorizeddns.org"
		$Host52 = "www.edu.onmypc.org"
		$Host53 = "www.fgtr.info"
		$Host54 = "www.hot.mrface.com"
		$Host55 = "www.ktry.info"
		$Host56 = "www.lucy.justdied.com"
		$Host57 = "www.osk.lflink.com"
		$Host58 = "www.reg.dsmtp.com"
		$Host59 = "www.tt0320.portrelay.com"
		$Host60 = "www.lockheedmartin.com"
	condition:
		$SHA2561 or $SHA2562 or $Host1 or $IP1 or $IP2 or $IP3 or $IP4 or $IP5 or $IP6 or $IP7 or $IP8 or $IP9 or $IP10 or $IP11 or $IP12 or $IP13 or $IP14 or $IP15 or $IP16 or $IP17 or $IP18 or $IP19 or $Host2 or $Host3 or $Host4 or $MD51 or $MD52 or $MD53 or $IP20 or $IP21 or $Host5 or $Host6 or $Host7 or $Host8 or $Host9 or $Host10 or $Host11 or $Host12 or $Host13 or $Host14 or $Host15 or $Host16 or $Host17 or $Host18 or $Host19 or $Host20 or $Host21 or $Host22 or $Host23 or $Host24 or $Host25 or $Host26 or $Host27 or $Host28 or $Host29 or $Host30 or $Host31 or $Host32 or $Host33 or $Host34 or $Host35 or $Host36 or $Host37 or $Host38 or $Host39 or $MD54 or $MD55 or $MD56 or $URL1 or $URL2 or $Filename1 or $Filename2 or $Host40 or $Host41 or $Host42 or $Host43 or $Host44 or $Host45 or $Host46 or $Host47 or $Host48 or $Host49 or $Host50 or $Host51 or $Host52 or $Host53 or $Host54 or $Host55 or $Host56 or $Host57 or $Host58 or $Host59 or $Host60
}