rule keydnap_downloader {
meta:
        description = "OSX/Keydnap Downloader"
        author = "Marc-Etienne M.Léveillé"
        date = "2016-07-06"
        reference = "http:www.welivesecurity.com/2016/07/06/new-osxkeydnap-malware-is-hungry-for-credentials"
        version = "1"

    strings:
        $ = "icloudsyncd"
        $ = "killall Terminal"
        $ = "open %s"
    
    condition:
        2 of them
}

rule keydnap_backdoor_packer {
meta:
        description = "OSX/Keydnap packed backdoor"
        author = "Marc-Etienne M.Léveillé"
        date = "2016-07-06"
        reference = "http:www.welivesecurity.com/2016/07/06/new-osxkeydnap-malware-is-hungry-for-credentials"
        version = "1"

    strings:
        $upx_string = "This file is packed with the UPX"
        $packer_magic = "ASS7"
        $upx_magic = "UPX!"
        
    condition:
        $upx_string and $packer_magic and not $upx_magic
}

rule keydnap_backdoor {
meta:
        description = "Unpacked OSX/Keydnap backdoor"
        author = "Marc-Etienne M.Léveillé"
        date = "2016-07-06"
        reference = "http:www.welivesecurity.com/2016/07/06/new-osxkeydnap-malware-is-hungry-for-credentials"
        version = "1"

    strings:
        $ = "api/osx/get_task"
        $ = "api/osx/cmd_executed"
        $ = "Loader-"
        $ = "u2RLhh+!LGd9p8!ZtuKcN"
        $ = "com.apple.iCloud.sync.daemon"
    condition:
        2 of them
}

