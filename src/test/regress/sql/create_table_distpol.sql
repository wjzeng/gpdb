-- Test effective distribution policy after different variants of CREATE TABLE

-- start_ignore
CREATE SCHEMA create_table_distpol;
SET search_path TO create_table_distpol;
-- end_ignore

-- Make sure random default distribution works for CTAS
SET gp_create_table_random_default_distribution=on;
DROP TABLE IF EXISTS distpol;
create table distpol as select random(), 1 as a, 2 as b;

select attrnums from gp_distribution_policy where localoid = 'distpol'::regclass;


-- Test RANDOM default distribution with AS clause containing a SELECT block
CREATE TABLE distpol_hobbies_r (
  name text,
  person text
);

CREATE TABLE distpol_bar AS SELECT * FROM distpol_hobbies_r;

select attrnums from gp_distribution_policy where localoid='distpol_bar'::regclass;

-- Test RANDOM distribution with ON COMMIT option
begin;

create temp table r3_1 on commit preserve rows as select 10 as a1, 20 as b1, 30 as c1, 40 as d1;
select attrnums from gp_distribution_policy where localoid='r3_1'::regclass;

create temp table r3_2 on commit delete rows as select 10 as a2, 20 as b2, 30 as c2, 40 as d2;
select attrnums from gp_distribution_policy where localoid='r3_2'::regclass;

create temp table r3_3 on commit drop as select 10 as a3, 20 as b3, 30 as c3, 40 as d3;
select attrnums from gp_distribution_policy where localoid='r3_3'::regclass;

end;

RESET gp_create_table_random_default_distribution;

-- Test that distribution policy is not inherited and it is RANDOM in CREATE TABLE with default distribution set to random
SET gp_create_table_random_default_distribution=on;
CREATE TABLE distpol_person (
  name      text,
  age       int4,
  location  point
) DISTRIBUTED BY (name);

CREATE TABLE distpol_staff_member (
  salary    int4,
  manager   name
) INHERITS (distpol_person) WITH OIDS;
select attrnums from gp_distribution_policy where localoid = 'distpol_staff_member'::regclass;

CREATE TABLE distpol_student (
  gpa      float8
) INHERITS (distpol_person);
select attrnums from gp_distribution_policy where localoid = 'distpol_student'::regclass;

CREATE TABLE distpol_stud_emp (
  percent  int4
) INHERITS (distpol_staff_member, distpol_student);
select attrnums from gp_distribution_policy where localoid = 'distpol_stud_emp'::regclass;

RESET gp_create_table_random_default_distribution;

-- Test that LIKE clause does not affect default distribution
SET gp_create_table_random_default_distribution=on;
set client_min_messages='warning';
DROP TABLE IF EXISTS distpol_person CASCADE;
reset client_min_messages;
CREATE TABLE distpol_person (
  name      text,
  age       int4,
  location  point
) DISTRIBUTED BY (name);
select attrnums from gp_distribution_policy where localoid = 'distpol_person'::regclass;

CREATE TABLE distpol_person_copy (LIKE distpol_person);
select attrnums from gp_distribution_policy where localoid = 'distpol_person_copy'::regclass;

RESET gp_create_table_random_default_distribution;

-- Test duplicate distribute keys
CREATE TABLE ctas_dup_dk as SELECT distinct age as c1, age as c2 from distpol_person; 
SELECT distinct age c1, age c2 into ctas_dup_dk_1 from distpol_person;


--
-- Test deriving distribution key from the query's distribution in
-- CREATE TABLE AS
--
create temporary table foo (i int) distributed by (i);

-- In both these cases, the query results are distributed by foo.i. In the
-- first case, it becomes a table column, so it's chosen as the distribution
-- key. In the second case, it's not, so we follow the default rule to use
-- the first column. (That's with the Postgres planner. ORCA uses different
-- rules.)
create table distpol_ctas1 as select 1 as col1, i from (select i from foo) x;
create table distpol_ctas2 as select 1 as col1 from (select i from foo) x;

-- Multiple columns. All the query's distribution key columns have to become
-- table columns, otherwise we can't use it.
drop table foo;
create temporary table foo (i int, j int) distributed by (i, j);
create table distpol_ctas3 as select 1 as col1, i from (select i, j from foo) x;
create table distpol_ctas4 as select 1 as col1, i, j from (select i, j from foo) x;

-- Check the results.
select localoid::regclass, attrnums from gp_distribution_policy where localoid::regclass::text like 'distpol_ctas%';

-- Check distribution keys for inherited tables with the same columns as in a parent table
CREATE TABLE points (
    p     point
) distributed randomly;

CREATE TABLE a_points (
    p     point,
    a     int
) INHERITS (points) distributed by (a);
select attrnums from gp_distribution_policy where localoid = 'a_points'::regclass;

CREATE TABLE b_points (
    b     int,
    p     point,
    c     int
) INHERITS (points) distributed by (b, c);
select attrnums from gp_distribution_policy where localoid = 'b_points'::regclass;

CREATE TABLE c_points (
    b     int,
    p     point,
    d     int,
    c     int
) INHERITS (points, b_points, a_points) distributed by (b, c);
select attrnums from gp_distribution_policy where localoid = 'c_points'::regclass;

-- Check distribution on non-hashable column in a parent table
CREATE TABLE c_points (
    c     int
) INHERITS (points) distributed by (p);
