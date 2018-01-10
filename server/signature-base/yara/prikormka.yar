// Operation Groundbait yara rules
// For feedback or questions contact us at: github@eset.com
// https://github.com/eset/malware-ioc/
//
// These yara rules are provided to the community under the two-clause BSD
// license as follows:
//
// Copyright (c) 2016, ESET
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

private rule PrikormkaDropper
{
    strings:
        $mz = { 4D 5A }

        $kd = "KDSTORAGE" wide
        $kd = "KDSTORAGE_64" wide
        $kd = "KDRUNDRV32" wide
        $kd = "KDRAR" wide

        $bin = {69 65 04 15 00 14 1E 4A 16 42 08 6C 21 61 24 0F}
        $bin = {76 6F 05 04 16 1B 0D 5E 0D 42 08 6C 20 45 18 16}
        $bin = {4D 00 4D 00 43 00 00 00 67 00 75 00 69 00 64 00 56 00 47 00 41 00 00 00 5F 00 73 00 76 00 67 00}

        $inj = "?AVCinj2008Dlg@@" ascii
        $inj = "?AVCinj2008App@@" ascii
    condition:
        ($mz at 0) and ((any of ($bin)) or (3 of ($kd)) or (all of ($inj)))
}

private rule PrikormkaModule
{
    strings:
        $mz = { 4D 5A }

        // binary
        $str = {6D 70 2E 64 6C 6C 00 53 74 61 72 74 69 6E 67 00}
        $str = {68 6C 70 75 63 74 66 2E 64 6C 6C 00 43 79 63 6C 65}
        $str = {00 6B 6C 2E 64 6C 6C 00 53 74 61 72 74 69 6E 67 00}
        $str = {69 6F 6D 75 73 2E 64 6C 6C 00 53 74 61 72 74 69 6E 67}
        $str = {61 74 69 6D 6C 2E 64 6C 6C 00 4B 69 63 6B 49 6E 50 6F 69 6E 74}
        $str = {73 6E 6D 2E 64 6C 6C 00 47 65 74 52 65 61 64 79 46 6F 72 44 65 61 64}
        $str = {73 63 72 73 68 2E 64 6C 6C 00 47 65 74 52 65 61 64 79 46 6F 72 44 65 61 64}

        // encrypted
        $str = {50 52 55 5C 17 51 58 17 5E 4A}
        $str = {60 4A 55 55 4E 53 58 4B 17 52 57 17 5E 4A}
        $str = {55 52 5D 4E 5B 4A 5D 17 51 58 17 5E 4A}
        $str = {60 4A 55 55 4E 61 17 51 58 17 5E 4A}
        $str = {39 5D 17 1D 1C 0A 3C 57 59 3B 1C 1E 57 58 4C 54 0F}

        // mutex
        $str = "ZxWinDeffContex" ascii wide
        $str = "Paramore756Contex43" wide
        $str = "Zw_&one@ldrContext43" wide

        // other
        $str = "A95BL765MNG2GPRS"

        // dll names
        $str = "helpldr.dll" wide fullword
        $str = "swma.dll" wide fullword
        $str = "iomus.dll" wide fullword
        $str = "atiml.dll"  wide fullword
        $str = "hlpuctf.dll" wide fullword
        $str = "hauthuid.dll" ascii wide fullword

        // rbcon
        $str = "[roboconid][%s]" ascii fullword
        $str = "[objectset][%s]" ascii fullword
        $str = "rbcon.ini" wide fullword

        // files and logs
        $str = "%s%02d.%02d.%02d_%02d.%02d.%02d.skw" ascii fullword
        $str = "%02d.%02d.%02d_%02d.%02d.%02d.%02d.rem" wide fullword

        // pdb strings
        $str = ":\\!PROJECTS!\\Mina\\2015\\" ascii
        $str = "\\PZZ\\RMO\\" ascii
        $str = ":\\work\\PZZ" ascii
        $str = "C:\\Users\\mlk\\" ascii
        $str = ":\\W o r k S p a c e\\" ascii
        $str = "D:\\My\\Projects_All\\2015\\" ascii
        $str = "\\TOOLS PZZ\\Bezzahod\\" ascii

    condition:
        ($mz at 0) and (any of ($str))
}

private rule PrikormkaEarlyVersion
{
    strings:
        $mz = { 4D 5A }

        $str = "IntelRestore" ascii fullword
        $str = "Resent" wide fullword
        $str = "ocp8.1" wide fullword
        $str = "rsfvxd.dat" ascii fullword
        $str = "tsb386.dat" ascii fullword
        $str = "frmmlg.dat" ascii fullword
        $str = "smdhost.dll" ascii fullword
        $str = "KDLLCFX" wide fullword
        $str = "KDLLRUNDRV" wide fullword
    condition:
        ($mz at 0) and (2 of ($str))
}

rule Prikormka
{
    meta:
        Author      = "Anton Cherepanov"
        Date        = "2016/05/10"
        Description = "Operation Groundbait"
        Source = "https://github.com/eset/malware-ioc/"
        Contact = "threatintel@eset.com"
        License = "BSD 2-Clause"
    condition:
        PrikormkaDropper or PrikormkaModule or PrikormkaEarlyVersion
}
