rule ICS_Havex_backdoors
{
	strings:
		$Host1 = "malwr.com"
		$IP1 = "1.0.14.706"
		$Filename1 = "SwissrangerSetup1.0.14.706.exe"
		$Filename2 = "eCatcherSetup.exe"
		$Host2 = "www.ewon.biz"
		$SHA2561 = "398a69b8be2ea2b4a6ed23a55459e0469f657e6c7703871f63da63fb04cefe90"
		$MD51 = "e027d4395d9ac9cc980d6a91122d2d83"
		$SHA2562 = "70103c1078d6eb28b665a89ad0b3d11c1cbca61a05a18f87f6a16c79b501dfa9"
		$MD52 = "eb0dacdc8b346f44c8c370408bad4306"
		$IP2 = "3.0.0.82"
		$Filename3 = "egrabitsetup.exe"
		$Host3 = "www.mbconnectline.com"
		$SHA2563 = "0007ccdddb12491e14c64317f314c15e0628c666b619b10aed199eefcfe09705"
		$MD53 = "1080e27b83c37dfeaa0daaa619bdf478"
		$Filename4 = "setup_1.0.1.exe"
		$SHA2564 = "c32277fba70c82b237a86e9b542eb11b2b49e4995817b7c2da3ef67f6a971d4a"
		$MD54 = "0a9ae7fdcd9a9fe0d8c5c106e8940701"
		$Filename5 = "mbCHECK.exe"
		$SHA2565 = "0b74282d9c03affb25bbecf28d5155c582e246f0ce21be27b75504f1779707f5"
		$MD55 = "1d6b11f85debdda27e873662e721289e"
		$Filename6 = "setupvcom_lan2.exe"
		$URL1 = "http://netresec.com/?b=14ABDA4"
		$Host4 = "netresec.com"
	condition:
		$Host1 or $IP1 or $Filename1 or $Filename2 or $Host2 or $SHA2561 or $MD51 or $SHA2562 or $MD52 or $IP2 or $Filename3 or $Host3 or $SHA2563 or $MD53 or $Filename4 or $SHA2564 or $MD54 or $Filename5 or $SHA2565 or $MD55 or $Filename6 or $URL1 or $Host4
}