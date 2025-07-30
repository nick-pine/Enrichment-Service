 
rule AlwaysTrue {
    meta:
        description = "Example rule that always matches, for testing only."
    strings:
        $example = "example"
    condition:
        true
}