-- Don't dispatch 'client_encoding'
-- When client_encoding is dispatch to QE, error messages generated in QEs were
-- converted to client_encoding, but QD assumed that they were in server encoding,
-- it will leads to corruption. 

set client_encoding = 'latin1';
create function raise_error(t text) returns void as $$
begin
  raise exception 'raise_error called on "%"', t;
end;
$$ language plpgsql;

select raise_error('funny char ' || chr(196)) from gp_dist_random('gp_id');
reset client_encoding;

--
-- Test buildGpQueryString of cdbdisp_query.c truncates a query longer than QUERY_STRING_TRUNCATE_SIZE and containing
-- multi-byte symbols properly
--
set log_min_duration_statement to 0;
create table truncate_test ("колонка 1" int, "колонка 2" int, "колонка 3" int, "колонка 4" int, "колонка 5" int,
"колонка 6" int, "колонка 7" int, "колонка 8" int, "колонка 9" int, "колонка 10" int, "колонка 11" int,
"колонка 12" int, "колонка 13" int, "колонка 14" int, "колонка 15" int, "колонка 16" int, "колонка 17" int,
"колонка 18" int, "колонка 19" int, "колонка 20" int, "колонка 21" int, "колонка 22" int, "колонка 23" int,
"колонка 24" int, "колонка 25" int, "колонка 26" int, "колонка 27" int, "колонка 28" int, "колонка 29" int,
"колонка 30" int, "колонка 31" int, "колонка 32" int, "колонка 33" int, "колонка 34" int, "колонка 35" int,
"колонка 36" int, "колонка 37" int, "колонка 38" int, "колонка 39" int, "колонка 40" int, "особая колонка" int);
select logdebug from gp_toolkit.__gp_log_segment_ext where logdebug ilike
'%create table truncate_test%' and logdebug not ilike '%gp_toolkit.__gp_log_segment_ext%' order by logtime desc limit 1;
drop table truncate_test;
reset log_min_duration_statement;
