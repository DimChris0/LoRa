
rule PYTHON_SHELLCODE__DOWNLOADER_
{
    meta:
        short_description = "PYTHON SHELLCODE (DOWNLOADER)"
        description = "The shellcode launcher is a simple launcher which recieves an encoded shellcode buffer from its C2 server, allocates memory for it and then executes the shellcode.  The launcher is written in python and packaged with PyInstaller.  You can read more about this downloader at https://www.fireeye.com/blog/threat-research/2015/02/behind_the_syrianco.htmlhttps://www.fireeye.com/blog/threat-research/2015/02/behind_the_syrianco.html "
        authored_by = "FireEye"
        authored_date = "2015-01-27T19:56:21"
        category = "Downloader"
        license = "Apache 2.0"
        score = 80
        iocid = "0b879284-0c37-4bfa-9dd8-34505a9c5175"

    strings:
        $a89dc9cb15a542e69e497a7cc9ae1bf5 = "64a17f5177157bb8c4199d38c46ec93b"
        $452d566a78fb48ccbb9e47ae7234a1dd = "FacebookAccount"

    condition:
        $a89dc9cb15a542e69e497a7cc9ae1bf5  or $452d566a78fb48ccbb9e47ae7234a1dd
}
