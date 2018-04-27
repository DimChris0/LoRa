rule myrule
{
	strings:
		$String1 = "myvirus"

	condition:
    $String1
}
