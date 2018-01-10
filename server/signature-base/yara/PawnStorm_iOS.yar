rule PawnStorm_iOS
{
	strings:
		$SHA11 = "05298a48e4ca6d9778b32259c8ae74527be33815"
		$SHA12 = "176e92e7cfc0e57be83e901c36ba17b255ba0b1b"
		$SHA13 = "30e4decd68808cb607c2aba4aa69fb5fdb598c64"
	condition:
		$SHA11 or $SHA12 or $SHA13
}