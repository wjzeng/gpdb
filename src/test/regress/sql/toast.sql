
CREATE TABLE toastable_heap(a text, b varchar, c int) distributed randomly;
CREATE TABLE toastable_ao(a text, b varchar, c int) with(appendonly=true, compresslevel=1) distributed randomly;

-- INSERT 
-- uses the toast call to store the large tuples
INSERT INTO toastable_heap VALUES(repeat('a',100000), repeat('b',100001), 1);
INSERT INTO toastable_heap VALUES(repeat('A',100000), repeat('B',100001), 2);
INSERT INTO toastable_ao VALUES(repeat('a',100000), repeat('b',100001), 1);
INSERT INTO toastable_ao VALUES(repeat('A',100000), repeat('B',100001), 2);

-- Check that tuples were toasted and are detoasted correctly. we use
-- char_length() because it guarantees a detoast without showing tho whole result
SELECT char_length(a), char_length(b), c FROM toastable_heap ORDER BY c;
SELECT char_length(a), char_length(b), c FROM toastable_ao ORDER BY c;

-- UPDATE 
-- (heap rel only) and toast the large tuple
UPDATE toastable_heap SET a=repeat('A',100000), b=repeat('B',100001) WHERE c=1;
SELECT char_length(a), char_length(b) FROM toastable_heap ORDER BY c;

-- ALTER
-- this will cause a full table rewrite. we make sure the tosted values and references
-- stay intact after all the oid switching business going on.
ALTER TABLE toastable_heap ADD COLUMN d int DEFAULT 10;
ALTER TABLE toastable_ao ADD COLUMN d int DEFAULT 10;

SELECT char_length(a), char_length(b), c, d FROM toastable_heap ORDER BY c;
SELECT char_length(a), char_length(b), c, d FROM toastable_ao ORDER BY c;

-- TRUNCATE
-- remove reference to toast table and create a new one with different values
TRUNCATE toastable_heap;
TRUNCATE toastable_ao;

INSERT INTO toastable_heap VALUES(repeat('a',100002), repeat('b',100003), 2, 20);
INSERT INTO toastable_ao VALUES(repeat('a',100002), repeat('b',100003), 2, 20);

SELECT char_length(a), char_length(b), c, d FROM toastable_heap;
SELECT char_length(a), char_length(b), c, d FROM toastable_ao;

-- TODO: figure out a way to verify that toasted data is removed after the truncate.

DROP TABLE toastable_heap;
DROP TABLE toastable_ao;

-- TODO: figure out a way to verify that the toast tables are dropped

-- Test TOAST_MAX_CHUNK_SIZE changes for upgrade.
CREATE TABLE toast_chunk_test (a bytea);
ALTER TABLE toast_chunk_test ALTER COLUMN a SET STORAGE EXTERNAL;

-- Alter our TOAST_MAX_CHUNK_SIZE and insert a value we know will be toasted.
CREATE EXTENSION IF NOT EXISTS gp_inject_fault;
SELECT DISTINCT gp_inject_fault('decrease_toast_max_chunk_size', 'skip', dbid)
	   FROM pg_catalog.gp_segment_configuration
	   WHERE role = 'p';
INSERT INTO toast_chunk_test VALUES (repeat('abcdefghijklmnopqrstuvwxyz', 1000)::bytea);
SELECT DISTINCT gp_inject_fault('decrease_toast_max_chunk_size', 'reset', dbid)
	   FROM pg_catalog.gp_segment_configuration
	   WHERE role = 'p';

-- The toasted value should still be read correctly.
SELECT * FROM toast_chunk_test WHERE a <> repeat('abcdefghijklmnopqrstuvwxyz', 1000)::bytea;

-- Random access into the toast table should work equally well.
SELECT encode(substring(a from 521*26+1 for 26), 'escape') FROM toast_chunk_test;

CREATE TABLE test_reuse_detoasted_tuple(a int, b text) DISTRIBUTED BY (a);
INSERT INTO test_reuse_detoasted_tuple SELECT i, repeat('a' || i, 355448) FROM generate_series(1,2)i;
SET optimizer=off;

EXPLAIN SELECT DISTINCT ON (a,b) * FROM test_reuse_detoasted_tuple;

-- The Unique node in following query uses the previous tuple de-toasted by the
-- Gather Motion sender to compare with the new tuple obtained from the Sort
-- node for eliminating duplicates.
SELECT DISTINCT ON (a,b) a FROM test_reuse_detoasted_tuple;
