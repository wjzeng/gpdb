#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include "cmockery.h"

#include "../cdbcopy.c"

void
test__processCopyEndResults_handles_int64_aggregation(void **state)
{
	/* Initialize mock variables for the function call */
	CdbCopy *c;
	SegmentDatabaseDescriptor *db_descriptors;
	int *results;
	int size;
	SegmentDatabaseDescriptor *failedSegDBs;
	bool err_header;
	bool first_error;
	int failed_count;
	int total_rows_rejected;
	int64 total_rows_completed;

	/* Set up mock variables for the function call */
	SegDbState *segdb_state = malloc(sizeof(SegDbState));
	c = malloc(sizeof(CdbCopy));
	c->segdb_state = &segdb_state;
	db_descriptors = malloc(sizeof(SegmentDatabaseDescriptor));
	size = 1; /* just loop once */
	results = malloc(size * sizeof(int));
	results[0] = 1; /* skip "if (result == 0)" part */
	total_rows_rejected = 0;
	total_rows_completed = 0; /* we'll be asserting against this one */

	/* Set up PGresult mock as QE COPY response */
	PGresult *mock_result = malloc(sizeof(PGresult));
	mock_result->numRejected = 0;
	mock_result->numCompleted = PG_INT64_MAX;
	mock_result->aotupcounts = malloc(sizeof(PQaoRelTupCount));

	/* Mock out uninteresting function calls in processCopyEndResults*/
	expect_any(PQsocket, conn);
	will_return(PQsocket, -1);

	expect_any(PQisBusy, conn);
	will_return(PQisBusy, false);

	expect_any(PQgetResult, conn);
	will_return(PQgetResult, mock_result); /* dispatcher gets mock QE result */

	expect_any(PQstatus, conn);
	will_return(PQstatus, CONNECTION_OK);

	expect_any_count(PQresultStatus, res, -1);
	will_return_count(PQresultStatus, PGRES_TUPLES_OK, -1);

	expect_any(PQprocessAoTupCounts, parts);
	expect_any(PQprocessAoTupCounts, ht);
	expect_any(PQprocessAoTupCounts, aotupcounts);
	expect_any(PQprocessAoTupCounts, naotupcounts);
	will_return(PQprocessAoTupCounts, 0);

	expect_any(PQclear, res);
	will_be_called(PQclear);

	expect_any(PQgetResult, conn);
	will_return(PQgetResult, NULL); /* exit loop */

	expect_any(PQstatus, conn);
	will_return(PQstatus, CONNECTION_OK);

	/* Call the function of interest with our mock arguments */
	processCopyEndResults(c, db_descriptors, results, size, &failedSegDBs,
			      &err_header, &first_error, &failed_count,
			      &total_rows_rejected, &total_rows_completed);

	/* Assert that the dispatcher aggregated the QE values correctly */
	assert_true(total_rows_completed == PG_INT64_MAX);

	/* Cleanup malloc calls */
	free(mock_result->aotupcounts);
	free(mock_result);
	free(results);
	free(db_descriptors);
	free(c);
	free(segdb_state);
}

int
main(int argc, char* argv[])
{
	cmockery_parse_arguments(argc, argv);

	const UnitTest tests[] = {
		unit_test(test__processCopyEndResults_handles_int64_aggregation)
	};

	MemoryContextInit();

	return run_tests(tests);
}
