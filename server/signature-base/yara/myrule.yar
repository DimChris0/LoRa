rule Suspicious_Size_explorer_exe {
    meta:
        description = "Detects uncommon file size of explorer.exe"
        author = "Florian Roth"
        score = 60
        date = "2015-12-21"
    condition:
        filename == "explorer.exe"
        and ( filesize < 1000KB or filesize > 3000KB )
}
