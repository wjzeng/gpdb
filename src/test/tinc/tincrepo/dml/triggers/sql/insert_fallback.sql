-- @skip #140439825
--start_ignore
SET client_min_messages='log';
SET optimizer_log_failure = 'all';
INSERT INTO dml_trigger_table_1 VALUES('TEST',10);
SET client_min_messages='notice';
--end_ignore

SELECT * FROM dml_trigger_table_1 order by 2;

\!sed -n '/Pivotal/p' %MYD%/output/insert_fallback_orca.out
