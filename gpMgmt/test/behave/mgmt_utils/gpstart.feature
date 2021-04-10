@gpstart
Feature: Validate command line arguments

    Scenario: Entering an invalid argument
        When the user runs "gpstart -z"
        Then gpstart should print "no such option: -z" error message 
        And gpstart should return a return code of 2

    Scenario: Run gpstart
        Given the database is not running
        When the user runs "gpstart -a"
        Then gpstart should return a return code of 0
        And database "testdb" health check should pass on table "t1"

    #@dca # TODO: can this test be repurposed for a general cluster?
    #Scenario: gpstart with 1 host down
    #    Given we have determined the first segment hostname
    #    And the database is not running
    #    And eth2 on the first segment host is down
    #    And eth3 on the first segment host is down
    #    When the user runs "gpstart -a"
    #    Then gpstart should return a return code of 1
    #    And database "testdb" health check should pass on table "t1"
    #    And eth2 on the first segment host is up
    #    And eth3 on the first segment host is up
    #    And the user runs "gprecoverseg -a"
    #    And the segments are synchronized
    #    And the user runs "gprecoverseg -r"
    #    And the segments are synchronized

    Scenario: Remove MASTER_DATA_DIRECTORY from os.environ
        Given the database is not running
        And MASTER_DATA_DIRECTORY environment variable is not set
        When the user runs "gpstart -a"
        Then gpstart should return a return code of 2
        And gpstart should print "Environment Variable MASTER_DATA_DIRECTORY not set!" to stdout
        And MASTER_DATA_DIRECTORY environment variable should be restored
        
    
    # gpstart fails after hard shutdown of the system, the postmaster.pid file exists with a pid
    # that matches that of a currently running non-postgres pid
    # TODO: can this test be repurposed for a general cluster?
    #@dca
    #Scenario: Pid corresponds to a non postgres process 
    #    Given the database is running
    #    and all the segments are running
    #    and the segments are synchronized
    #    and the "primary" segment information is saved
    #    When the postmaster.pid file on "primary" segment is saved
    #    And the user runs "gpstop -a"
    #    And gpstop should return a return code of 0
    #    And the background pid is killed on "primary" segment
    #    When we run a sample background script to generate a pid on "primary" segment
    #    And we generate the postmaster.pid file with the background pid on "primary" segment
    #    Then the user runs "gpstart -a -v"
    #    And gpstart should return a return code of 0
    #    And all the segments are running
    #    and the segments are synchronized
    #    And the backup pid file is deleted on "primary" segment
    #    And the background pid is killed on "primary" segment

    Scenario: Pid does not correspond to any running process 
        Given the database is running
        And all the segments are running
        and the segments are synchronized
        and the "primary" segment information is saved
        When the postmaster.pid file on "primary" segment is saved
        And the user runs "gpstop -a"
        And gpstop should return a return code of 0
        And we generate the postmaster.pid file with a non running pid on the same "primary" segment
        Then the user runs "gpstart -a"
        And gpstart should return a return code of 0
        And all the segments are running
        and the segments are synchronized
        And the backup pid file is deleted on "primary" segment
 
    Scenario: Starting DB when one mirror segment is already up
        Given the database is running
        And all the segments are running
        and the segments are synchronized
        and the "mirror" segment information is saved
        When the user runs "gpstop -a"
        And gpstop should return a return code of 0
        And the user starts one "mirror" segment
        Then the user runs "gpstart -a"
        And gpstart should return a return code of 0
        And all the segments are running
        and the segments are synchronized

    Scenario: gpstart correctly identifies down segments
        Given the database is running
          And a mirror has crashed
          And the database is not running
         When the user runs "gpstart -a"
         Then gpstart should return a return code of 0
          And gpstart should print "Skipping startup of segment marked down in configuration" to stdout
          And gpstart should print "Skipped segment starts \(segments are marked down in configuration\) += 1" to stdout
          And gpstart should print "Successfully started [0-9]+ of [0-9]+ segment instances, skipped 1 other segments" to stdout
          And gpstart should print "Number of segments not attempted to start: 1" to stdout
         # Cleanup
         Then the user runs "gprecoverseg -a"

    Scenario: gpstart starts even if the standby host is unreachable
        Given the database is running
          And the temporary filespace is moved
          And the catalog has a standby master entry

         When the standby host is made unreachable
          And the user runs command "pkill -9 postgres"
          And "gpstart" is run with prompts accepted

         Then gpstart should print "Continue only if you are certain that the standby is not acting as the master." to stdout
          And gpstart should print "No standby master configured" to stdout
          And gpstart should return a return code of 0
          And all the segments are running

    Scenario: gpstart starts even if segment hosts for two primaries is unreachable
      Given the database is running
      And the host for the primary on content 0 is made unreachable
      And the host for the primary on content 1 is made unreachable
      And the user runs command "pkill -9 postgres" on all hosts without validation

      When "gpstart" is run with prompts accepted

     Then gpstart should print "Host invalid_host is unreachable" to stdout
      And gpstart should print unreachable host messages for the down segments
      And the status of the primary on content 0 should be "d"
      And the status of the primary on content 1 should be "d"
      And the cluster is returned to a good state

    # Once the mirror is marked down, gpstart will not start it.  In this case, connections
    # to the cluster are not allowed. Hence, we do not check here for the states of the primary
    # or mirror here after we restart the cluster.  The step to restart the cluster taks about
    # 12 minutes.
    Scenario: gpstart starts even if segment hosts for a primary and mirror are unreachable
        Given the database is running
          And the host for the primary on content 0 is made unreachable
          And the host for the mirror on content 1 is made unreachable
          And the user runs command "pkill -9 postgres" on all hosts without validation

         When "gpstart" is run with prompts accepted

         Then gpstart should print "Host invalid_host is unreachable" to stdout
          And gpstart should print unreachable host messages for the down segments
          And the cluster is returned to a good state
