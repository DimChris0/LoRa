rule OperationClandestineWolf
{
	strings:
		$URL1 = "hxxp://<subdomain>.<legitdomain>.<TLD>/<directory>/<alphanumericID>.html"
	condition:
		$URL1
}