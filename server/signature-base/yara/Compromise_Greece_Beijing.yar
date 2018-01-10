rule Compromise_Greece_Beijing
{
	strings:
		$URL1 = "https://twitter.com/PhysicalDrive0/status/479921770838102017"
		$URL2 = "http://www.grpressbeijing.com/1.jar"
		$Filename1 = "1.jar"
		$Host1 = "www.grpressbeijing.com"
		$SHA2561 = "b832e4b5a4829c8df6de7b42c5cb32ef25b5ab59072b4c2a7838404cd0dd5e5f"
		$Registry1 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet"
		$Registry2 = "HKCU\\Software\\Microsoft\\Internet"
		$IP1 = "208.115.124.83"
		$Filename2 = "cmd.exe"
		$Host2 = "defense.miraclecz.com"
		$URL3 = "http://www.motobit.com/util/base64-decoder-encoder.asp"
		$Host3 = "www.motobit.com"
		$SHA2562 = "a4863f44f48d1c4c050dd7baad767a86b348dd4d33924acf4e0a3cd40c6ae29f"
		$URL4 = "http://buy.miraclecz.com"
		$Filename3 = "spoolsv.exe"
		$Host4 = "buy.miraclecz.com"
		$Registry3 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
		$URL5 = "https://www.dropbox.com/s/ckr7p5kka62cc7s/Embassy%20of%20Greece%20-%20Beijing.zip"
		$IP2 = "74.121.191.33"
		$Filename4 = "20Beijing.zip"
	condition:
		$URL1 or $URL2 or $Filename1 or $Host1 or $SHA2561 or $Registry1 or $Registry2 or $IP1 or $Filename2 or $Host2 or $URL3 or $Host3 or $SHA2562 or $URL4 or $Filename3 or $Host4 or $Registry3 or $URL5 or $IP2 or $Filename4
}