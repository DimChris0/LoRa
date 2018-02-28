rule P2P_PlugX_Analysis
{
	strings:
		$Host1 = "jpcert.or.jp"
		$SHA2561 = "bc65e2859f243ff45b12cd184bfed7b809f74e67e5bb61bc92ed94058d3d2515"
		$SHA2562 = "93c85a8dd0becc4e396eea2dc15c0010ff58d2b873d44fd7e45711a27cfe613b"
		$SHA2563 = "0ff134057a8b2e31b148fedfdd185f5b1a512149499a8c5c0915cf10b10a613e"
	condition:
		$Host1 or $SHA2561 or $SHA2562 or $SHA2563
}