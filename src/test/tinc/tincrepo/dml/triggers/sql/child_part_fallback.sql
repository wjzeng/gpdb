--start_ignore
SET client_min_messages='log';
SET optimizer_log_failure = 'all';
INSERT INTO dml_trigger_table VALUES('TEST',10);
SET client_min_messages='notice';
--end_ignore

SELECT * FROM dml_trigger_table order by 2;

\!sed -n '/Pivotal/p' %MYD%/output/child_part_fallback_orca.out
