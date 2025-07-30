 
    meta:
        description = "Example rule that always matches, for testing only."
    strings:
        $example = "example"
    condition:
        true
}

rule ExampleStringMatch {
    meta:
        description = "Matches the string 'example' for testing."
    strings:
        $example = "example"
    condition:
        $example
}