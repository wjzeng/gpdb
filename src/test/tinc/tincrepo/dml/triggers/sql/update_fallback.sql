SELECT * FROM dml_trigger_table_1 order by 2;

--start_ignore
SET client_min_messages='log';
SET optimizer_log_failure = 'all';
UPDATE dml_trigger_table_1 set name='NEW TEST' where name='TEST';
SET client_min_messages='notice';
--end_ignore

SELECT * FROM dml_trigger_table_1 order by 2;

\!sed -n '/Pivotal/p' %MYD%/output/update_fallback_orca.out
