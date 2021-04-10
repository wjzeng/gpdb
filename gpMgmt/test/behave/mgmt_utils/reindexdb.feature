@reindexdb
Feature: Reindex tests

    @test
    Scenario: reindexdb outputs SQL with properly quoted database names
        Given database "1234mydb" is dropped and recreated
        When the user runs "reindexdb -s -d 1234mydb --echo"
        Then reindexdb should print "REINDEX SYSTEM \"1234mydb\"" to stdout
