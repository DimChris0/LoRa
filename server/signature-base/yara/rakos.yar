rule linux_rakos {
meta:
        description = "Linux/Rakos.A executable"
        author = "Peter Kálnai"
        date = "2016-12-13"
        reference = "http:www.welivesecurity.com/2016/12/20/new-linuxrakos-threat-devices-servers-ssh-scan/"
        version = "1"
        contact = "threatintel@eset.com"
        license = "BSD 2-Clause"


    strings:
        $ = "upgrade/vars.yaml"
        $ = "MUTTER"
        $ = "/tmp/.javaxxx"
        $ = "uckmydi"

    condition:
        3 of them
}

