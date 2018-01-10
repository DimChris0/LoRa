
rule APT28_DOMAINS__REPORT_
{
    meta:
        short_description = "APT28 DOMAINS (REPORT)"
        description = "Domains used by APT28."
        authored_by = "FireEye"
        authored_date = "2014-10-17T02:04:34"
        threatcategory = "APT"
        threatgroup = "APT28"
        license = "Apache 2.0"
        iocid = "0ff58bf9-1c07-42f6-b135-b18c139f631a"

    strings:
        $54481c42effb436bb4d2cff1cbd09a66 = /kavkazcentr.info/ 
        $b8b742d55dff4f0fbda80c878c1dd1e1 = /rnil.am/ 
        $af36c9b3d55446de9525c05a0759a399 = /standartnevvs.com/ 
        $389c9c03eaf4425994e5623334cea26e = /novinitie.com/ 
        $c17d001cdf8940ff87dee89bde9f1425 = /n0vinite.com/ 
        $115031bff3424bd09f9ca5d8e1111281 = /qov.hu.com/ 
        $201da5bac3274e9bb0afdb1632d742cb = /q0v.pl/ 
        $d69b1fb1f31e49e29ae1e4d5057d2142 = /mail.g0v.pl/ 
        $7a1dc5b6f55544e2b6a3efd334183f9c = /poczta.mon.q0v.pl/ 
        $ca3b91fe36ec475497fd65f36739f4d1 = /baltichost.org/ 
        $3b9f2b02916847a894b4cc1f5ec505d4 = /nato.nshq.in/ 
        $798874dc102b4c5abd486e07362c7211 = /natoexhibitionff14.com/ 
        $196515ec4c17406ba067503a175914ed = /login-osce.org/ 
        $63c696e5a98b4459aeeab88124e6ed29 = /smigroup-online.co.uk/ 

    condition:
        $54481c42effb436bb4d2cff1cbd09a66  or $b8b742d55dff4f0fbda80c878c1dd1e1  or $af36c9b3d55446de9525c05a0759a399  or $389c9c03eaf4425994e5623334cea26e  or $c17d001cdf8940ff87dee89bde9f1425  or $115031bff3424bd09f9ca5d8e1111281  or $201da5bac3274e9bb0afdb1632d742cb  or $d69b1fb1f31e49e29ae1e4d5057d2142  or $7a1dc5b6f55544e2b6a3efd334183f9c  or $ca3b91fe36ec475497fd65f36739f4d1  or $3b9f2b02916847a894b4cc1f5ec505d4  or $798874dc102b4c5abd486e07362c7211  or $196515ec4c17406ba067503a175914ed  or $63c696e5a98b4459aeeab88124e6ed29 
}

rule BLACKSTAR__FAMILY_
{
    meta:
        short_description = "BLACKSTAR (FAMILY)"
        description = "BLACKSTAR is a dropper which extracts and executes a second dropper in memory, called REDDWARF.  REDDWARF then extractes an obfuscated copy of the DarkComet backdoor and executes it in memory; before writing itself (REDDWARF) to disk and setting a persistence mechanism.  DarkComet contains standard backdoor functionality such as manipulating processes, services, the registry, and uploading and downloading files, as well as control of webcams and microphones.  You can read more about these droppers at https://www.fireeye.com/blog/threat-research/2015/02/behind_the_syrianco.htmlhttps://www.fireeye.com/blog/threat-research/2015/02/behind_the_syrianco.html"
        authored_by = "FireEye"
        authored_date = "2015-01-21T20:20:24"
        family = "BLACKSTAR"
        category = "Dropper"
        license = "Apache 2.0"
        iocid = "6bb9ce5b-94c1-4733-8bb8-dc5be775b190"

    strings:
        $8165f3e6a355460db1a7b6ca634c635f = /de65eed45ac210c66db8082f1a72db8f/ 
        $27b3cea2e78b44deaa10b0c6df2cf341 = /7576127f8bd805b30d0016d897211f54/ 
        $75963603302442a68ce98e5685ee6abf = /e11aeb603cb7a31c2028976a2deed550/ 
        $9bb66cdc4ac84a2b8d79d40950f55ac0 = /7247d42b3b4632dc7ed9d8559596fff8/ 
        $c1b215b733414a6798b296ebd8291e71 = /a691e4b629da2b37dd87e760bfb0106e/ 
        $c8b506938f0a4ca884519f01b06c9899 = /d1f817744f79dad415a526c4ce51bed9/ 
        $243fff5db9e449bbbb2ba58fbf7fe5e2 = /202eb180f5faa8460941ae60cf63da63/ 
        $9bcf50c77f204b8985f6dba1e2023772 = /64eb08013399e3ac18c936d361d80e17/ 
        $02ccd273b28544e28872327427604ea0 = /163595b20debdeccdeaf4cb14fba737c/ 
        $bf3af89a3bcc4dca9200981f18e68f2e = /97a35a7471e0951ee4ed8581d2941601/ 
        $1150b11ea69b4f51bd892b66e78108a5 = /c421f4e12892d4ac345e7b03f6a053d2/ 
        $22711234887543dda64d4bf8aac922ac = /39632325327bf21f7d9cf02caf065646/ 
        $06cfab9d88bc458d966f28992c85960e = /60aa1cdb1df16179b88be8cf8dbbaf14/ 
        $a88bab44ce4049d48608bba61b85ef99 = /89dda79018d6216970a274b16b3494ad/ 
        $72e0f40d0fdc4ea1b507719e931dc15c = /a641c08e09c53858d16c0c70107979b5/ 
        $60d189fabbcf414a925d53a2933f3ad0 = /adobereadersetup-86x.exe/ 
        $f92182f4668e4e1382c945a16d82159c = /adobesetup.exe/ 
        $70f4d41b0acf4d5581b6ba832b1be0b5 = /adobe32en.exe/ 
        $225ba8dfeafe4b91b7c26f24a40ae43f = /adobereadersetup-86x.exe/ 
        $15ee1b296d774dd391b5a4917a4d246c = /adobex86setup.sfx.exe/ 
        $dde04d4fad3b477daa63f7535f38d5ae = /google-update.exe/ 
        $9d66a38a5b6a427e879001ce803bef27 = /adobereader-86x.exe/ 
        $b2e58810e7344860a83e7f3935e44243 = /adobesetupx86.exe/ 
        $e8de756570144852920d3b4ac0784f4d = /adobred-86x.exe/ 
        $7cc04535b2ff4ed5b7857ec3c8254133 = /adobereader-86x-64x.exe/ 
        $9f7b0e7624f34718a15e63b2a2731edb = /adobeflash.exe/ 
        $1bf624738c2946b59388dfea1503bbe2 = /adobesetup32.exe/ 
        $7d71ba3649f5416085a9afb8ed67eb09 = /adobeinsx86.exe/ 
        $b2a39f22bf3c4c239136fa1c4af6d6d8 = /adobesetupx86.exe/ 
        $750f0e36a94a4077abeed103cca742ea = /microtec.exe/ 
        $921927e6915f4c7db0d8f451a1bca3bb = /DC_MUTEX/ 
        $81a2f561aff949dc9928312832cd584c = /CurrentVersion\Run/ 
        $bcca7791fdd4494792d308fff6d2cce1 = /1/ 

    condition:
        $8165f3e6a355460db1a7b6ca634c635f  or $27b3cea2e78b44deaa10b0c6df2cf341  or $75963603302442a68ce98e5685ee6abf  or $9bb66cdc4ac84a2b8d79d40950f55ac0  or $c1b215b733414a6798b296ebd8291e71  or $c8b506938f0a4ca884519f01b06c9899  or $243fff5db9e449bbbb2ba58fbf7fe5e2  or $9bcf50c77f204b8985f6dba1e2023772  or $02ccd273b28544e28872327427604ea0  or $bf3af89a3bcc4dca9200981f18e68f2e  or $1150b11ea69b4f51bd892b66e78108a5  or $22711234887543dda64d4bf8aac922ac  or $06cfab9d88bc458d966f28992c85960e  or $a88bab44ce4049d48608bba61b85ef99  or $72e0f40d0fdc4ea1b507719e931dc15c  or $60d189fabbcf414a925d53a2933f3ad0  or $79da1c475afa46e093ea1de47b5b0bd7  or $d90f69bcec364ca780a5802257098eae  or $f92182f4668e4e1382c945a16d82159c  or $70f4d41b0acf4d5581b6ba832b1be0b5  or $225ba8dfeafe4b91b7c26f24a40ae43f  or $15ee1b296d774dd391b5a4917a4d246c  or $dde04d4fad3b477daa63f7535f38d5ae  or $9d66a38a5b6a427e879001ce803bef27  or $b2e58810e7344860a83e7f3935e44243  or $e8de756570144852920d3b4ac0784f4d  or $7cc04535b2ff4ed5b7857ec3c8254133  or $9f7b0e7624f34718a15e63b2a2731edb  or $1bf624738c2946b59388dfea1503bbe2  or $7d71ba3649f5416085a9afb8ed67eb09  or $b2a39f22bf3c4c239136fa1c4af6d6d8  or $750f0e36a94a4077abeed103cca742ea  or $921927e6915f4c7db0d8f451a1bca3bb  or ($81a2f561aff949dc9928312832cd584c  and $bcca7791fdd4494792d308fff6d2cce1  and $2dda338b455642c690f4e5a9dd9ffc37 )
}

rule ADS_GONE_BAD__BLOG_
{
    meta:
        short_description = "ADS GONE BAD (BLOG)"
        description = "This IOC contains indicators detailed in the blog post "Ads Gone Bad" that can be read here: https://www.fireeye.com/blog/threat-research/2015/03/ads_gone_bad.html. This IOC contains indicators for domains, IP addresses and a filename used for a malvertising campaign that employs malicious SWF files. The attacker used the CVE-2014-0569 exploit in order to deliver malicious payloads to victims."
        authored_by = "FireEye"
        authored_date = "2015-03-02T16:17:41"
        category = "Exploit"
        category = "Downloader"
        license = "Apache 2.0"
        iocid = "4fdb0f45-8151-4941-a9e1-a31e21000659"

    strings:
        $faea31ac920c4513a2efc1552b94f1b9 = /adserver.alltraveldaily.com/ 
        $8f11f953ba99422a9fb0b9972320251f = /adserver.mensstylebook.com/ 
        $c4790daa0dd749b899997694e4134d51 = /adserver.recipechart.com/ 
        $d904da6b41784d46a6eb05d52626a075 = /adserver.highspeedtesting.com/ 
        $d8d0d7e346554aa5a23cd65a292c91af = /adserver.smackchow.com/ 
        $32495270ffa04175822cfc6ba56a4475 = /adserver.easygoodhealth.com/ 
        $d0dcc9e89b2e4c47aa2911468e6ab04f = /adserver.1000bites.com/ 
        $7b84f1ac32ee48cfbfc549141aa6f8e4 = /adserver.rawdaily.com/ 
        $8e6d8f26f9774e44b38ed2c1e13ccdad = /adserver.diyfoodvids.com/ 
        $34bd9b786773479c94cfbd7575bf0477 = /adserver.worldtotravel.com/ 
        $a6545968108d45ea9dab74752e4b7feb = /adserver.diybaker.com/ 
        $a52df07af9eb4ad8b1341eea41fd3e1c = /adserver.trendingwoman.com/ 
        $b39c2db0b8934e83a7fc33d81623e6f2 = /adserver.quickmensguide.com/ 
        $aeca6ecd64fa45aaad6a0566aade623c = /adserver.citybartender.com/ 
        $fbdd49e0cd6d45af9e10108e057ed943 = /adserver.hometechproducts.com/ 
        $bcd07dc168a6467a9eab8bb9c67da550 = /adserver.streetzsavvy.com/ 
        $20ed6e55fa574eecb5dcb72e8f7868d1 = /adserver.whyresearch.com/ 
        $349147f5deb3497fbd154250a531cda3 = /adserver.moviesland.com/ 
        $605baf65c13c4d1ea5cdab3ca56deefe = /adserver.femaleinsider.com/ 
        $2904c0b471304054806fd9acd8d854a3 = /adserver.ie-games.com/ 
        $fd7e45bbde444f3dbc9f599f4de58424 = /adserver.elegantrecipes.com/ 
        $b806b0250d7d4661a0452105e0113f9e = /yieidmanager.com/ 
        $79d7e58f834a4324a0dbe9219a523247 = /184.174.122.30/ 
        $7d522ae45c6e41e6a2dc2266f1f3f1b6 = /184.174.124.168/ 
        $34acfb7df1674f61b06b01c112e62539 = /184.174.122.54/ 
        $ed4bcd84fff24048ac2673db1bf8da30 = /184.174.124.169/ 
        $b1551619cf1040ce8e53f418ad6a3de7 = /198.55.119.125/ 
        $6f14a60e48f14749a25f41efe6afb46c = /198.55.119.126/ 
        $5d5b654b2e9c4cf58fa42ed37827dcde = /66.55.129.199/ 
        $d6eb390c11e746d981fe4028d387e89b = /?d=300x250/ 
        $4444d4d3910b4acea11bdf3b719584da = /ee2un066aepv4.php/ 
        $e6ed767731944f878a1bb79da28f456b = /user_6290/ 
        $1e7561109da8498ba06b9133289cd259 = /user_6302/ 
        $982f932e623f49f2ac8401bbd19e2fa7 = /camp_3698/ 
        $baf46317ae6d4eb48427601f955f4526 = /camp_3693/ 
        $256834da3d0343f6b1b8b3478d69b873 = /camp_3674/ 
        $57095c6a946c477fb2736e875be279c2 = /camp_3709/ 
        $bae8713baeb94f109d29f474a8b113f4 = /camp_3830/ 

    condition:
        $faea31ac920c4513a2efc1552b94f1b9  or $8f11f953ba99422a9fb0b9972320251f  or $c4790daa0dd749b899997694e4134d51  or $d904da6b41784d46a6eb05d52626a075  or $d8d0d7e346554aa5a23cd65a292c91af  or $32495270ffa04175822cfc6ba56a4475  or $d0dcc9e89b2e4c47aa2911468e6ab04f  or $7b84f1ac32ee48cfbfc549141aa6f8e4  or $8e6d8f26f9774e44b38ed2c1e13ccdad  or $34bd9b786773479c94cfbd7575bf0477  or $a6545968108d45ea9dab74752e4b7feb  or $a52df07af9eb4ad8b1341eea41fd3e1c  or $b39c2db0b8934e83a7fc33d81623e6f2  or $aeca6ecd64fa45aaad6a0566aade623c  or $fbdd49e0cd6d45af9e10108e057ed943  or $bcd07dc168a6467a9eab8bb9c67da550  or $20ed6e55fa574eecb5dcb72e8f7868d1  or $349147f5deb3497fbd154250a531cda3  or $605baf65c13c4d1ea5cdab3ca56deefe  or $2904c0b471304054806fd9acd8d854a3  or $fd7e45bbde444f3dbc9f599f4de58424  or $b806b0250d7d4661a0452105e0113f9e  or $79d7e58f834a4324a0dbe9219a523247  or $7d522ae45c6e41e6a2dc2266f1f3f1b6  or $34acfb7df1674f61b06b01c112e62539  or $ed4bcd84fff24048ac2673db1bf8da30  or $b1551619cf1040ce8e53f418ad6a3de7  or $6f14a60e48f14749a25f41efe6afb46c  or $5d5b654b2e9c4cf58fa42ed37827dcde  or $d6eb390c11e746d981fe4028d387e89b  or $4444d4d3910b4acea11bdf3b719584da  or (($e6ed767731944f878a1bb79da28f456b  or $1e7561109da8498ba06b9133289cd259 ) and ($982f932e623f49f2ac8401bbd19e2fa7  or $baf46317ae6d4eb48427601f955f4526  or $256834da3d0343f6b1b8b3478d69b873  or $57095c6a946c477fb2736e875be279c2  or $bae8713baeb94f109d29f474a8b113f4 ))
}

rule YABROD__DOWNLOADER_
{
    meta:
        short_description = "YABROD (DOWNLOADER)"
        description = "YABROD is the first stage of a two stage downloader.  The downloader downloads the second stage, CABLECAR, which uses a PDF embedded in the YABROD binary to extract shellcode and inject it into processes.  This injected shellcode downloads and executes a file, while setting a persistence mechanism for the downloaded file.  This downloaded file will then extract shellcode for the Metasploit Meterpreter and execute that shellcode.  You can read more about these downloaders at https://www.fireeye.com/blog/threat-research/2015/02/behind_the_syrianco.htmlhttps://www.fireeye.com/blog/threat-research/2015/02/behind_the_syrianco.html"
        authored_by = "FireEye"
        authored_date = "2015-01-27T22:07:02"
        family = "YABROD"
        family = "CABLECAR"
        category = "Downloader"
        license = "Apache 2.0"
        iocid = "5a8d6878-2649-4ddc-a1f6-c98932a54f91"

    strings:
        $2131173ad5e34715864777630f3390f7 = /Keyboard-Sounds.exe/ 
        $2955c667201d4327a3c62f06230fc9e1 = /VPN7.exe/ 
        $f5b3aa2ae21e4bb7bd2a3b8e4c3aba2f = /0e24a0060493bcb85ce4a5110550f204/ 
        $a3814c2068544481b7139013201767da = /1328d3d4872bfe2c98fd7b672d8dff1b/ 
        $76cf7f3a59354892a4b74d445c848087 = /508deeb6a5a37e9f94d5d4733ce0352f/ 
        $abded3e6a46c499d8233273b8861d003 = /ba02f98166f1fd960d1371b74f4bb367/ 
        $bd9c63c168fa4561adbf6035b26155e1 = /bc167bca4ca3cf6f2f2bd7e90ecdeb29/ 
        $c03667da7de1490585fe1acf9a53e904 = /bd4769f37de88321a9b64e5f85baf1ef/ 
        $87a8b5c6361a424e9e112ceffc515a57 = /e0625817eb11874d806909a8c190d45a/ 
        $00ad2b0170fa4f5fab33cb3284f4a320 = /f18dedf9f5d213deba18a2e037819ea1/ 
        $a5c99e543cfe4eadacd501986248e8b7 = /44df02ac28d80deb45f5c7c48b56a858/ 
        $acf5842efcf2469b87e3a944901b5df1 = /78c5670e2cee9b5c3b88aa9cb27519be/ 
        $9d08c7a0cb39482288a77bfbea72c299 = /9d351b9ee731d88f12fcaa64010e828d/ 
        $31f8316a25614c98a312cd3e346a6a1e = /greenhill.png/ 
        $c3e935d9f0e14188816f6a2333547263 = /reporthezbolla20072013_pdf.exe/ 
        $d264c1bca64c48f1a8398cd225b2ffe5 = /bayan09072013_pdf.exe/ 
        $15f8b852b32e4aa391ac43f3062e9ec0 = /182c7b1ad894852d23f4de538e59ac2b/ 
        $88eb6792d1424850b37f945f1a90844e = /4e007cb87626f0093a84ed50b1d27a7f/ 

    condition:
        $e6a78908cbb14b1d806633dee72d0cee  or $7f1fcdcd3a9e4dbf8363c727ae2bbba9  or $d6d7a314411e49309542564ea40ccb79  or $7d2af5e28293408aa819c7ae5d61f6d5  or $2131173ad5e34715864777630f3390f7  or $2955c667201d4327a3c62f06230fc9e1  or $f5b3aa2ae21e4bb7bd2a3b8e4c3aba2f  or $a3814c2068544481b7139013201767da  or $76cf7f3a59354892a4b74d445c848087  or $abded3e6a46c499d8233273b8861d003  or $bd9c63c168fa4561adbf6035b26155e1  or $c03667da7de1490585fe1acf9a53e904  or $87a8b5c6361a424e9e112ceffc515a57  or $00ad2b0170fa4f5fab33cb3284f4a320  or $a5c99e543cfe4eadacd501986248e8b7  or $acf5842efcf2469b87e3a944901b5df1  or $9d08c7a0cb39482288a77bfbea72c299  or $31f8316a25614c98a312cd3e346a6a1e  or $c3e935d9f0e14188816f6a2333547263  or $d264c1bca64c48f1a8398cd225b2ffe5  or $15f8b852b32e4aa391ac43f3062e9ec0  or $88eb6792d1424850b37f945f1a90844e 
}

