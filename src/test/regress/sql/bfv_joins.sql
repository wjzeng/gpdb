--
-- Set up
--
drop table if exists x;
drop table if exists y;
drop table if exists z;
drop table if exists t;
drop table if exists t1;
drop table if exists t2;

create table x (a int, b int, c int);
insert into x values (generate_series(1,10), generate_series(1,10), generate_series(1,10));
create table y (a int, b int, c int);
insert into y (select * from x);

CREATE TABLE t1 (a int, b int);
CREATE TABLE t2 (a int, b int);

INSERT INTO t1 VALUES (1,1),(2,1),(3,NULL);
INSERT INTO t2 VALUES (2,3);

CREATE FUNCTION func_x(x int) RETURNS int AS $$
BEGIN
RETURN $1 +1;
END
$$ LANGUAGE plpgsql;

create table z(x int) distributed by (x);

CREATE TABLE bfv_joins_foo AS SELECT i as a, i+1 as b from generate_series(1,10)i;
CREATE TABLE bfv_joins_bar AS SELECT i as c, i+1 as d from generate_series(1,10)i;
CREATE TABLE t AS SELECT bfv_joins_foo.a,bfv_joins_foo.b,bfv_joins_bar.d FROM bfv_joins_foo,bfv_joins_bar WHERE bfv_joins_foo.a = bfv_joins_bar.d;

CREATE FUNCTION my_equality(a int, b int) RETURNS BOOL
    AS $$ SELECT $1 < $2 $$
    LANGUAGE SQL;

create table x_non_part (a int, b int, c int);
insert into x_non_part select i%3, i, i from generate_series(1,10) i;

create table x_part (e int, f int, g int) partition by range(e) (start(1) end(5) every(1), default partition extra);
insert into x_part select generate_series(1,10), generate_series(1,10) * 3, generate_series(1,10)%6;

analyze x_non_part;
analyze x_part;

--
-- Test with more null-filtering conditions for LOJ transformation in Orca
--
SELECT * from x left join y on True where y.a > 0;

SELECT * from x left join y on True where y.a > 0 and y.b > 0;

SELECT * from x left join y on True where y.a in (1,2,3);

SELECT * from x left join y on True where y.a = y.b ;

SELECT * from x left join y on True where y.a is NULL;

SELECT * from x left join y on True where y.a is NOT NULL;

SELECT * from x left join y on True where y.a is NULL and Y.b > 0;

SELECT * from x left join y on True where func_x(y.a) > 0;

SELECT * FROM t1 LEFT OUTER JOIN t2 ON t1.a = t2.a WHERE t1.b IS DISTINCT FROM t2.b;

SELECT * FROM t1 LEFT OUTER JOIN t2 ON t1.a = t2.a WHERE t1.b IS DISTINCT FROM NULL;

SELECT * FROM t1 LEFT OUTER JOIN t2 ON t1.a = t2.a WHERE t2.b IS DISTINCT FROM NULL;

SELECT * FROM t1 LEFT OUTER JOIN t2 ON t1.a = t2.a WHERE t2.b IS NOT DISTINCT FROM NULL;

SELECT * FROM t1 LEFT OUTER JOIN t2 ON t1.a = t2.a WHERE t1.b IS NOT DISTINCT FROM NULL;

-- Test for unexpected NLJ qual
--
explain select 1 as mrs_t1 where 1 <= ALL (select x from z);

--
-- Test for wrong results in window functions under joins #1
--
select * from
(SELECT bfv_joins_bar.*, AVG(t.b) OVER(PARTITION BY t.a ORDER BY t.b desc) AS e FROM t,bfv_joins_bar) bfv_joins_foo, t
where e < 10
order by 1, 2, 3, 4, 5, 6;

--
-- Test for wrong results in window functions under joins #2
--
select * from (
SELECT cup.*, SUM(t.d) OVER(PARTITION BY t.b) FROM (
	SELECT bfv_joins_bar.*, AVG(t.b) OVER(PARTITION BY t.a ORDER BY t.b desc) AS e FROM t,bfv_joins_bar
) AS cup,
t WHERE cup.e < 10
GROUP BY cup.c,cup.d, cup.e ,t.d, t.b) i
order by 1, 2, 3, 4;

--
-- Test for wrong results in window functions under joins #3
--
select * from (
WITH t(a,b,d) as (SELECT bfv_joins_foo.a,bfv_joins_foo.b,bfv_joins_bar.d FROM bfv_joins_foo,bfv_joins_bar WHERE bfv_joins_foo.a = bfv_joins_bar.d )
SELECT cup.*, SUM(t.d) OVER(PARTITION BY t.b) FROM (
	SELECT bfv_joins_bar.*, AVG(t.b) OVER(PARTITION BY t.a ORDER BY t.b desc) AS e FROM t,bfv_joins_bar
) as cup,
t WHERE cup.e < 10
GROUP BY cup.c,cup.d, cup.e ,t.d,t.b) i
order by 1, 2, 3, 4;

--
-- Query on partitioned table with range join predicate on part key causes fallback to planner
--
select * from x_part, x_non_part where a > e;
select * from x_part, x_non_part where a <> e;
select * from x_part, x_non_part where a <= e;
select * from x_part left join x_non_part on (a > e);
select * from x_part right join x_non_part on (a > e);
select * from x_part join x_non_part on (my_equality(a,e));

--
-- Clean up
--
drop table if exists x;
drop table if exists y;
drop function func_x(int);
drop table if exists z;
drop table if exists bfv_joins_foo;
drop table if exists bfv_joins_bar;
drop table if exists t;
drop table if exists x_non_part;
drop table if exists x_part;
drop function my_equality(int, int);


-- Bug-fix verification for MPP-25537: PANIC when bitmap index used in ORCA select
CREATE TABLE mpp25537_facttable1 (
  col1 integer,
  wk_id smallint,
  id integer
)
with (appendonly=true, orientation=column, compresstype=zlib, compresslevel=5)
partition by range (wk_id) (
  start (1::smallint) END (20::smallint) inclusive every (1),
  default partition dflt
);

insert into mpp25537_facttable1 select col1, col1, col1 from (select generate_series(1,20) col1) a;

CREATE TABLE mpp25537_dimdate (
  wk_id smallint,
  col2 date
);

insert into mpp25537_dimdate select col1, current_date - col1 from (select generate_series(1,20,2) col1) a;

CREATE TABLE mpp25537_dimtabl1 (
  id integer,
  col2 integer
);

insert into mpp25537_dimtabl1 select col1, col1 from (select generate_series(1,20,3) col1) a;

CREATE INDEX idx_mpp25537_facttable1 on mpp25537_facttable1 (id);

set optimizer_analyze_root_partition to on;

ANALYZE mpp25537_facttable1;
ANALYZE mpp25537_dimdate;
ANALYZE mpp25537_dimtabl1;

SELECT count(*)
FROM mpp25537_facttable1 ft, mpp25537_dimdate dt, mpp25537_dimtabl1 dt1
WHERE ft.wk_id = dt.wk_id
AND ft.id = dt1.id;

--
-- Test NLJ with join conds on distr keys using equality, IS DISTINCT FROM & IS NOT DISTINCT FROM exprs
--
create table nlj1 (a int, b int);
create table nlj2 (a int, b int);

insert into nlj1 values (1, 1), (NULL, NULL);
insert into nlj2 values (1, 5), (NULL, 6);

set optimizer_enable_hashjoin=off;
set enable_hashjoin=off; set enable_mergejoin=off; set enable_nestloop=on;

explain select * from nlj1, nlj2 where nlj1.a = nlj2.a;
select * from nlj1, nlj2 where nlj1.a = nlj2.a;

explain select * from nlj1, nlj2 where nlj1.a is not distinct from nlj2.a;
select * from nlj1, nlj2 where nlj1.a is not distinct from nlj2.a;

explain select * from nlj1, (select NULL a, b from nlj2) other where nlj1.a is not distinct from other.a;
select * from nlj1, (select NULL a, b from nlj2) other where nlj1.a is not distinct from other.a;

explain select * from nlj1, nlj2 where nlj1.a is distinct from nlj2.a;
select * from nlj1, nlj2 where nlj1.a is distinct from nlj2.a;

reset optimizer_enable_hashjoin;
reset enable_hashjoin; reset enable_mergejoin; reset enable_nestloop;
drop table nlj1, nlj2;

-- Test colocated equijoins on coerced distribution keys
CREATE TABLE coercejoin (a varchar(10), b varchar(10)) DISTRIBUTED BY (a);
-- Positive test, the join should be colocated as the implicit cast from the
-- parse rewrite is a relabeling (varchar::text).
EXPLAIN SELECT * FROM coercejoin a, coercejoin b WHERE a.a=b.a;
-- Negative test, the join should not be colocated since the cast is a coercion
-- which cannot guarantee that the coerced value would hash to the same segment
-- as the uncoerced tuple.
EXPLAIN SELECT * FROM coercejoin a, coercejoin b WHERE a.a::numeric=b.a::numeric;

-- Do not push down any implied predicates to the Left Outer Join
DROP TABLE IF EXISTS member;
DROP TABLE IF EXISTS member_group;
DROP TABLE IF EXISTS member_subgroup;
DROP TABLE IF EXISTS region;

CREATE TABLE member(member_id int NOT NULL, group_id int NOT NULL) DISTRIBUTED BY(member_id);
CREATE TABLE member_group(group_id int NOT NULL) DISTRIBUTED BY(group_id);
CREATE TABLE region(region_id char(4), county_name varchar(25)) DISTRIBUTED BY(region_id);
CREATE TABLE member_subgroup(subgroup_id int NOT NULL, group_id int NOT NULL, subgroup_name text) DISTRIBUTED RANDOMLY;

INSERT INTO region SELECT i, i FROM generate_series(1, 200) i;
INSERT INTO member_group SELECT i FROM generate_series(1, 15) i;
INSERT INTO member SELECT i, i%15 FROM generate_series(1, 10000) i;
--start_ignore
ANALYZE member;
ANALYZE member_group;
ANALYZE region;
ANALYZE member_subgroup;
--end_ignore
EXPLAIN SELECT member.member_id
FROM member
INNER JOIN member_group
ON member.group_id = member_group.group_id
INNER JOIN member_subgroup
ON member_group.group_id = member_subgroup.group_id
LEFT OUTER JOIN region
ON (member_group.group_id IN (12,13,14,15) AND member_subgroup.subgroup_name = region.county_name);


DROP TABLE member;
DROP TABLE member_group;
DROP TABLE member_subgroup;
DROP TABLE region;

--
-- Test the query have equivalence class with const members.
-- Mix timestamp and timestamptz in a join. We cannot use a Redistribute
-- Motion, because the cross-datatype = operator between them doesn't belong
-- to any hash operator class. We cannot hash rows in a way that matches would
-- land on the same segment in that case.
--
CREATE TABLE gp_timestamp1 (a int, b timestamp) DISTRIBUTED BY (a, b);
CREATE TABLE gp_timestamp2 (c int, d timestamp) DISTRIBUTED BY (c, d);

INSERT INTO gp_timestamp1 SELECT i, timestamp '2016/11/06' + i * interval '1 day' FROM generate_series(1, 12) i;
INSERT INTO gp_timestamp1 SELECT i, timestamp '2016/11/09' FROM generate_series(1, 12) i;
INSERT INTO gp_timestamp2 SELECT i, timestamp '2016/11/06' + i * interval '1 day' FROM generate_series(1, 12) i;

ANALYZE gp_timestamp1;
ANALYZE gp_timestamp2;

-- col b is type of timestamp, but const is type of timestamptz. Their hash values are not compatible
SELECT a, b FROM gp_timestamp1 JOIN gp_timestamp2 ON a = c AND b = timestamptz '2016/11/09' order by a;
-- col b is type of timestamp, so is const. Their hash values are compatible
SELECT a, b FROM gp_timestamp1 JOIN gp_timestamp2 ON a = c AND b = timestamp '2016/11/09' order by a;
-- Another variation: There are two constants in the same equivalence class. One's
-- datatype is compatible with the distribution key, the other's is not. We can
-- redistribute based on the compatible constant.
SELECT a, b FROM gp_timestamp1 JOIN gp_timestamp2 ON a = c AND b = timestamptz '2016/11/09' AND b = timestamp '2016/11/09' order by a;

-- Similar case. Here, the =(float8, float4) cross-type operator would not be
-- hashable in 5X, since they use different hash functions. Check function
-- cdbhash() for details.
-- Note that in 6X and above, float8 and float4 have the same hash values when
-- they are equal by default (except legacy cdbhash opclass). Check catalog
-- pg_amop for detailed compatibility. The legacy cdbhash opclass refers to
-- cdbhash in 5X. For example, legacy cdbhash opclass includes cdbhash_integer_ops,
-- cdbhash_float4_ops and cdbhash_float8_ops, which means all integer are compatible,
-- but float4 and float8 are not compatible.
CREATE TABLE gp_f1 (a int, b float4) DISTRIBUTED BY (a, b);
CREATE TABLE gp_f2 (c int, d float4) DISTRIBUTED BY (c, d);

INSERT INTO gp_f1 SELECT i, i FROM generate_series(1, 12) i;
INSERT INTO gp_f1 SELECT i, 3 FROM generate_series(1, 12) i;
INSERT INTO gp_f2 SELECT i, i FROM generate_series(1, 12) i;

ANALYZE gp_f1;
ANALYZE gp_f2;

-- col b is type of float4, but const is type of float8. Their hash values are not compatible
SELECT a, b FROM gp_f1 JOIN gp_f2 ON a = c AND b = 3.0::float8 order by a;
-- col b is type of float4, so is const. Their hash values are compatible
SELECT a, b FROM gp_f1 JOIN gp_f2 ON a = c AND b = 3.0::float4 order by a;
-- Another variation: There are two constants in the same equivalence class. One's
-- datatype is compatible with the distribution key, the other's is not. We can
-- redistribute based on the compatible constant.
SELECT a, b FROM gp_f1 JOIN gp_f2 ON a = c AND b = 3.0::float8 AND b = 3.0::float4 order by a;

DROP TABLE gp_timestamp1;
DROP TABLE gp_timestamp2;
DROP TABLE gp_f1;
DROP TABLE gp_f2;
