SELECT * FROM dml_trigger_table_1 order by 2;

--start_ignore
SET optimizer_log_failure = 'all';
SET client_min_messages='log';
DELETE FROM dml_trigger_table_1 where age=10;
SET client_min_messages='notice';
--end_ignore

SELECT * FROM dml_trigger_table_1 order by 2;

\!sed -n '/Pivotal/p' %MYD%/output/delete_fallback_orca.out
