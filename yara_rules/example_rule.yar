rule ExampleRule {
    meta:
        description = "Example YARA rule for demonstration purposes"
    strings:
        $a = "malicious_string"
    condition:
        $a
}
