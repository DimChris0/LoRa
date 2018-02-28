rule Sanesecurity_TestSig_Type4_Hdr_2
{
    meta:
        author = "Sanesecurity"
        date = "01/07/2015"
        description = "Sanesecurity Yara Test signatures"

strings:
	$a0 = { 5375626a6563743a[0-30]727267363355686a32554379454363727558374438334134716435554135766e6c67774a70366236666d505a704f625a4a4162667465687568524158466279 }

condition:
	$a0
}

rule Sanesecurity_TestSig_Type3_Bdy_4
{
    meta:
        author = "Sanesecurity"
        date = "01/07/2015"
        description = "Sanesecurity Yara Test signatures"

strings:
	$a0 = { 626f64795f727267363375686a32756379656363727578376438336134716435756135766e6c67776a70366236666d707a706f627a6a61626674656875687261786662797a7a7a7a7a }

condition:
	$a0
}

rule Sanesecurity_TestSig_Type4_Bdy_3
{
    meta:
        author = "Sanesecurity"
        date = "01/07/2015"
        description = "Sanesecurity Yara Test signatures"

strings:
	$a0 = { 626f64795f727267363355686a32554379454363727558374438334134716435554135766e6c67774a70366236666d505a30616a646a6b776a6e535344667364667364666e77657264 }

condition:
	$a0
}
rule Sanesecurity_PhishingTestSig_1
{
    meta:
        author = "Sanesecurity"
        date = "01/07/2015"
        description = "Sanesecurity Yara Test signatures"

strings:
	$a0 = { 3c73616e6573656375726974793e64723161796c6172696164696178215f216c6562725f61776f6577696568693573316f6170726f38796c2363686c6163376975746f657a6f75716c75766975643c2f73616e6573656375726974793e }

condition:
	$a0
}
