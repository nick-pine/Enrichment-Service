rule SuspiciousProcessName {
    meta:
        description = "Detects suspicious process names"
    strings:
        $proc1 = "mimikatz"
        $proc2 = "powershell.exe"
    condition:
        any of ($proc*)
}

rule CreditCardPattern {
    meta:
        description = "Detects credit card number patterns"
    strings:
        $visa = /4[0-9]{12}(?:[0-9]{3})?/
        $mc = /5[1-5][0-9]{14}/
    condition:
        $visa or $mc
}

rule Base64EncodedExe {
    meta:
        description = "Detects base64 encoded executable headers"
    strings:
        $mz = "TVqQAAMAAAAEAAAA"
    condition:
        $mz
}
