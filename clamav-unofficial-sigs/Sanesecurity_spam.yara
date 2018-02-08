rule Sanesecurity_Spam_test //yara test
		                         
{
	strings:	
			
		$match1 = "this is a test rules from Sanesecurity"
		
	condition:
                $match1
}

rule Sanesecurity_Spam_pornspam //block some porn spam
		                         
{
	strings:	
			
		$matcha="F@cking"
                $matchb="c0ck"
                $matchc="pu$$y"
                $matchd="$ex"
                $matche="p0rn"
                $matchf="$luts" 
                $matchg="h00kers"
                $matchh="cre@mpied"
                $matchi="f@ck"
                $matchj="f@cials"
                $matchk="b00bs"
                $matchl="@ss"
                $matchm="bl0wjob"
                $matchn="deepthr0at"
                $matcho="a$$"
                $matchp="pu**y"
                $matchq="F*ck"
                $matchr="nymph0"
                $matchs="h00kup"
                $matcht="wh0re"
                $matchu="@nal"
                $matchv="h*rd"
                $httpmatch = "[ http:"
                $mailmatch = "X-Mailer: PHPMailer 5.2.9"
                
		
	condition:
                
                $httpmatch and $mailmatch and any of ($match*)
}                                              