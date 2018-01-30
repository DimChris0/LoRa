rule Suspicious_Size_explorer_exe {
    meta:
        description = "Detects uncommon file size of explorer.exe"
        author = "Florian Roth"
        score = 50
        date = "2015-12-21"
    condition:
        filename == "svchost" or filename == "svchost.exe"
}
