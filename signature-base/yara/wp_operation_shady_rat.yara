rule wp_operation_shady_rat
{
	strings:
		$URL1 = "http://twitter.com/DmitriCyber"
	condition:
		$URL1
}