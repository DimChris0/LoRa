
rule JumpExample
{
    meta:
        short_description = "JumpExample"
        authored_date = "2013-07-27T23:08:09Z"
        iocid = "50daf970-66cf-40e1-ada3-063dec5dbd27"

    strings:
        $a38341bd04084da5916faca5739a66f0 = { F4 23 [4-6] 62 B4 }

    condition:
        $a38341bd04084da5916faca5739a66f0 
}

