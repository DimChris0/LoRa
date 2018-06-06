rule NTLM_Dump_Output {
meta:
      description = "NTML Hash Dump output file - John/LC format"
      author = "Florian Roth"
      date = "2015-10-01"
      score = 75
   strings:
      $s0 = "500:AAD3B435B51404EEAAD3B435B51404EE:" ascii
      $s1 = "500:aad3b435b51404eeaad3b435b51404ee:" ascii
   condition:
      1 of them
}

rule Gsecdump_password_dump_file {
meta:
      description = "Detects a gsecdump output file"
      author = "Florian Roth"
      reference = "https://t.co/OLIj1yVJ4m"
      date = "2018-03-06"
      score = 65
   strings:
      $x1 = "Administrator(current):500:" ascii
   condition:
      uint32be(0) == 0x41646d69 and filesize < 3000 and $x1 at 0
}

