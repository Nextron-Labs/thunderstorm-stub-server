rule TestRule
{
    meta:
        description = "Test rule matching the stub server test sample"
        author      = "thunderstorm-stub-server"
        score       = 90
    strings:
        $marker = "THUNDERSTORM_TEST_MATCH_STRING" nocase
    condition:
        $marker
}
