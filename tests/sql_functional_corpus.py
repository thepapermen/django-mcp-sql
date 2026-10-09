"""Corpus for `test_sql_functional_corpus.py` (data only, no tests).

FUNCTIONAL: ordinary analytical Postgres queries that must run through
`run_query` unchanged. The first part is grouped by category; the second is
the reviewers' corpora (audit-verify/opus-review3/probes/corpus.txt and
corpus2.txt), filtered to valid Postgres that the package accepts on both
supported sqlglot versions.

The data has NULLs, partly-NULL rows and mixed-case text (rows 41-43 of t,
121-123 of u), so NULL handling, row comparisons and case are exercised too.

MIN_SERVER_VERSION: entries that need a newer Postgres than the oldest one
CI runs (functions added in 15 / 16, the PG16 numeric constants); skipped on
older servers.

POSTGRES_REJECTS: queries the package accepts and runs as written, which
Postgres itself rejects (no such function, a quoted name that does not
exist, a negative LIMIT, ...). They must fail in Postgres through
`run_query` too, not be translated into something that runs.

REFUSED: queries from those corpora the package refuses, with the reason —
by design (SELECT *, OFFSET / FETCH, set-returning functions, catalog and
identity functions, locking reads, recursive CTEs) or because the input is
not Postgres SQL / not parseable by sqlglot. Listed so the boundary stays
visible and reviewable.
"""

# The tables the corpus reads: see `SETUP_SQL`.
SETUP_SQL = "CREATE TABLE t (id int PRIMARY KEY, x numeric, y int, g text, d date, ts timestamptz, j jsonb, arr int[], b boolean, f float8, iv interval, tags text[]);\nINSERT INTO t SELECT i, i*1.37, i%7, chr(97 + i%4), DATE '2024-01-01' + i*3, TIMESTAMPTZ '2024-01-01 00:00+00' + i * INTERVAL '5 hours', jsonb_build_object('k', i, 'n', jsonb_build_object('m', i%3), 'a', jsonb_build_array(i, i+1)), ARRAY[i, i%3], i%2=0, i/3.0, i * INTERVAL '1 minute', ARRAY['x'||i%3, 'y'] FROM generate_series(1,40) i;\nCREATE TABLE u (id int PRIMARY KEY, t_id int, amount numeric, status text, created date);\nINSERT INTO u SELECT i, 1 + i%40, (i*7)%100 + 0.25, (ARRAY['open','closed','void'])[1+i%3], DATE '2024-01-01' + i FROM generate_series(1,120) i;\nINSERT INTO t (id, x, y, g, d, ts, j, arr, b, f, iv, tags) VALUES (41, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL), (42, 2.5, NULL, 'B', DATE '2024-03-01', NULL, '{\"k\": null, \"Key\": 1, \"\": 7, \"a''b\": 2, \"a\": [null, 1], \"n\": {\"\": 3, \"m\": null}}', ARRAY[NULL, 1]::int[], NULL, NULL, NULL, ARRAY['X', NULL]), (43, NULL, 3, 'Ab', NULL, TIMESTAMPTZ '2024-02-29 23:00+00', '{}', '{}', true, 0.5, NULL, '{}');\nINSERT INTO u (id, t_id, amount, status, created) VALUES (121, NULL, NULL, NULL, NULL), (122, 41, 5.5, 'Open', NULL), (123, 42, NULL, 'CLOSED', DATE '2024-02-29');\n"

# Operators reached as `OPERATOR(schema.op)` (review round 20): one name in
# schemas whose names fold differently, with different functions, so a
# rendering that loses the quotes picks another operator; and a prefix `!~`
# in `public` (bare `!~ x` is that operator to Postgres; sqlglot read `! ~x`).
OPERATOR_SCHEMAS = '"McpOps", mcpops, "mcp ops", "mcp""ops"'
SETUP_SQL += (
    f"DROP SCHEMA IF EXISTS {OPERATOR_SCHEMAS} CASCADE;\n"
    "DROP OPERATOR IF EXISTS public.!~ (NONE, text);\n"
    'CREATE SCHEMA "McpOps";\n'
    "CREATE SCHEMA mcpops;\n"
    'CREATE SCHEMA "mcp ops";\n'
    'CREATE SCHEMA "mcp""ops";\n'
    'CREATE OPERATOR "McpOps".= (LEFTARG = text, RIGHTARG = text, FUNCTION = pg_catalog.texteq);\n'
    "CREATE OPERATOR mcpops.= (LEFTARG = text, RIGHTARG = text, FUNCTION = pg_catalog.textne);\n"
    'CREATE OPERATOR "mcp ops".= (LEFTARG = text, RIGHTARG = text, FUNCTION = pg_catalog.text_lt);\n'
    'CREATE OPERATOR "mcp""ops".+ (LEFTARG = integer, RIGHTARG = integer, FUNCTION = pg_catalog.int4mi);\n'
    'CREATE OPERATOR "McpOps".- (RIGHTARG = integer, FUNCTION = pg_catalog.int4abs);\n'
    "CREATE OPERATOR mcpops.- (RIGHTARG = integer, FUNCTION = pg_catalog.int4um);\n"
    "CREATE OPERATOR public.!~ (RIGHTARG = text, FUNCTION = pg_catalog.upper);\n"
    f"GRANT USAGE ON SCHEMA {OPERATOR_SCHEMAS} TO PUBLIC;\n"
)
# Drops what `SETUP_SQL` creates.
TEARDOWN_SQL = (
    "DROP TABLE IF EXISTS t, u;\n"
    f"DROP SCHEMA IF EXISTS {OPERATOR_SCHEMAS} CASCADE;\n"
    "DROP OPERATOR IF EXISTS public.!~ (NONE, text);\n"
)

FUNCTIONAL: list[tuple[str, str]] = [
    (
        "aggregates",
        "SELECT mode() WITHIN GROUP (ORDER BY y) AS m, percentile_disc(0.5) WITHIN GROUP (ORDER BY x) AS pd FROM t",
    ),
    (
        "aggregates",
        "SELECT g, count(DISTINCT y) AS dy, round(avg(x), 3) AS ax, round(stddev(x), 3) AS sx, round(variance(x), 3) AS vx FROM t GROUP BY g HAVING count(*) > 5 ORDER BY g",
    ),
    (
        "aggregates",
        "SELECT bool_and(y > 0) AS all_pos, bool_or(y = 0) AS any_zero FROM t",
    ),
    (
        "aggregates",
        "SELECT g, string_agg(id::text, '-' ORDER BY id DESC) AS ids, array_agg(y ORDER BY id) AS ys FROM t WHERE id <= 8 GROUP BY g ORDER BY g",
    ),
    (
        "aggregates",
        "SELECT u.status, date_trunc('month', u.created) AS month, sum(u.amount) AS total, count(DISTINCT u.t_id) AS customers FROM u GROUP BY u.status, date_trunc('month', u.created) ORDER BY 1, 2",
    ),
    (
        "aggregates",
        "SELECT t.g, u.status, sum(u.amount) FILTER (WHERE u.amount > 20) AS big FROM t JOIN u ON u.t_id = t.id GROUP BY t.g, u.status ORDER BY 1, 2",
    ),
    (
        "grouping",
        "SELECT g, sum(y) AS s FROM t GROUP BY GROUPING SETS ((g), ()) ORDER BY g NULLS LAST",
    ),
    (
        "grouping",
        "SELECT g, b, count(*) AS n FROM t GROUP BY ROLLUP (g, b) ORDER BY g NULLS LAST, b NULLS LAST",
    ),
    (
        "grouping",
        "SELECT g, b, count(*) AS n, grouping(g, b) AS gr FROM t GROUP BY CUBE (g, b) ORDER BY g NULLS FIRST, b NULLS FIRST",
    ),
    (
        "numeric",
        "SELECT g, round(avg(x), 2) AS a, round(sum(x) / count(*), 4) AS b, abs(min(y) - 3) AS c, ceil(max(x)) AS ce, floor(min(x)) AS fl, mod(max(y), 4) AS md, power(2, 3) AS p, sqrt(16) AS sq FROM t GROUP BY g ORDER BY g",
    ),
    (
        "numeric",
        "SELECT width_bucket(x, 0, 60, 6) AS bucket, count(*) AS n FROM t GROUP BY 1 ORDER BY 1",
    ),
    (
        "windows",
        "SELECT id, y, avg(y) OVER (ORDER BY id ROWS BETWEEN 2 PRECEDING AND CURRENT ROW) AS mov, sum(y) OVER (PARTITION BY g ORDER BY id) AS run FROM t ORDER BY id",
    ),
    (
        "windows",
        "SELECT id, last_value(y) OVER (PARTITION BY g ORDER BY id RANGE BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING) AS lv FROM t ORDER BY id",
    ),
    (
        "windows",
        "SELECT id, y, lag(y) OVER w AS prev, lead(y) OVER w AS nxt, y - lag(y) OVER w AS delta FROM t WINDOW w AS (ORDER BY id) ORDER BY id LIMIT 10",
    ),
    (
        "windows",
        "SELECT g, id, row_number() OVER (PARTITION BY g ORDER BY id) AS rn, dense_rank() OVER (PARTITION BY g ORDER BY y) AS dr, ntile(3) OVER (ORDER BY id) AS nt FROM t ORDER BY g, id",
    ),
    (
        "windows",
        "SELECT id, first_value(id) OVER (PARTITION BY g ORDER BY id) AS fv, sum(x) OVER (ORDER BY d RANGE BETWEEN INTERVAL '6 days' PRECEDING AND CURRENT ROW) AS wk FROM t ORDER BY id",
    ),
    (
        "ctes",
        "WITH a AS (SELECT g, sum(y) AS s FROM t GROUP BY g), b AS (SELECT g, s, rank() OVER (ORDER BY s DESC, g) AS r FROM a) SELECT g, s, r FROM b WHERE r <= 3 ORDER BY r",
    ),
    (
        "ctes",
        "WITH outer_cte AS (WITH inner_cte AS (SELECT id, y FROM t WHERE y > 2) SELECT id, y * 2 AS y2 FROM inner_cte) SELECT count(*) AS n, sum(y2) AS s FROM outer_cte",
    ),
    (
        "joins",
        "SELECT t.id, latest.created FROM t CROSS JOIN LATERAL (SELECT u.created FROM u WHERE u.t_id = t.id ORDER BY u.created DESC LIMIT 1) AS latest WHERE t.id < 6 ORDER BY t.id",
    ),
    (
        "joins",
        "SELECT t.id, x.cnt FROM t LEFT JOIN LATERAL (SELECT count(*) AS cnt FROM u WHERE u.t_id = t.id AND u.status = 'open') AS x ON true WHERE t.id < 6 ORDER BY t.id",
    ),
    (
        "joins",
        "SELECT t.id, u.id AS uid FROM t FULL OUTER JOIN u ON u.t_id = t.id AND u.id < 3 WHERE t.id < 4 OR u.id < 3 ORDER BY t.id NULLS LAST, u.id NULLS LAST",
    ),
    (
        "joins",
        "SELECT t.id, u.amount FROM t RIGHT JOIN u ON u.t_id = t.id WHERE u.id < 5 ORDER BY u.id",
    ),
    (
        "joins",
        "SELECT a.id, b.id AS bid FROM t AS a JOIN t AS b ON b.id = a.id + 1 WHERE a.id < 5 ORDER BY a.id",
    ),
    (
        "subqueries",
        "SELECT t.id FROM t WHERE NOT EXISTS (SELECT 1 FROM u WHERE u.t_id = t.id AND u.status = 'void') ORDER BY t.id",
    ),
    (
        "subqueries",
        "SELECT id, (SELECT max(amount) FROM u WHERE u.t_id = t.id) AS mx FROM t WHERE id < 5 ORDER BY id",
    ),
    (
        "subqueries",
        "SELECT id FROM t WHERE id IN (SELECT t_id FROM u WHERE amount > 90) ORDER BY id",
    ),
    ("subqueries", "SELECT id FROM t WHERE y >= ALL (SELECT y FROM t) ORDER BY id"),
    (
        "conditionals",
        "SELECT id, CASE WHEN y < 2 THEN 'low' WHEN y < 5 THEN 'mid' ELSE 'high' END AS band, COALESCE(NULLIF(g, 'a'), 'none') AS g2, GREATEST(y, 3) AS gy, LEAST(y, 3) AS ly FROM t ORDER BY id",
    ),
    (
        "casts",
        "SELECT id, x::int AS xi, CAST(y AS text) AS yt, d::text AS dt, '42'::numeric(5, 2) AS n, CAST(ts AS date) AS td FROM t WHERE id < 4 ORDER BY id",
    ),
    (
        "datetime",
        "SELECT date_trunc('month', d) AS m, date_part('dow', d) AS dw, EXTRACT(YEAR FROM d) AS yr, age(DATE '2025-01-01', d) AS ag, make_date(2024, 2, 29) AS md FROM t WHERE id < 4 ORDER BY id",
    ),
    (
        "datetime",
        "SELECT id, d + INTERVAL '1 month' AS nm, ts - INTERVAL '2 hours' AS earlier, to_char(ts, 'YYYY-MM-DD HH24:MI') AS f, current_date - d AS days_ago FROM t WHERE id < 4 ORDER BY id",
    ),
    (
        "datetime",
        "SELECT id, now() - ts AS since, current_date AS today, date_trunc('week', ts) AS wk FROM t WHERE id < 3 ORDER BY id",
    ),
    (
        "datetime",
        "SELECT count(*) AS n FROM t WHERE ts >= now() - INTERVAL '100 years'",
    ),
    (
        "strings",
        "SELECT id, lower(g) AS lo, upper(g) AS up, trim('  ' || g || '  ') AS tr, substring('abcdef' FROM 2 FOR 3) AS ss, position('c' IN 'abcdef') AS pos FROM t WHERE id < 3 ORDER BY id",
    ),
    (
        "strings",
        "SELECT id, replace(g, 'a', 'A') AS rp, split_part('a-b-c', '-', 2) AS sp, regexp_replace('a1b2', '[0-9]', 'X', 'g') AS rr, regexp_match('a1b2', '[0-9]') AS rm FROM t WHERE id < 3 ORDER BY id",
    ),
    (
        "strings",
        "SELECT id, concat(g, '-', id) AS c, g || '/' || id AS c2, initcap('hello world') AS ic, left('abcdef', 2) AS l, right('abcdef', 2) AS r, length(g) AS len, format('%s=%s', g, id) AS f FROM t WHERE id < 3 ORDER BY id",
    ),
    (
        "patterns",
        "SELECT id FROM t WHERE g LIKE 'a%' OR g ILIKE 'B%' OR g SIMILAR TO '(c|d)' ORDER BY id",
    ),
    (
        "json",
        "SELECT id, j -> 'n' AS jn, j ->> 'k' AS jk, j #> '{n,m}' AS jm, j #>> '{a,0}' AS ja, j @> '{\"k\": 1}' AS has1, j ? 'k' AS hask FROM t WHERE id < 4 ORDER BY id",
    ),
    (
        "json",
        "SELECT jsonb_build_object('id', id, 'g', g) AS o, jsonb_array_length(j -> 'a') AS al FROM t WHERE id < 3 ORDER BY id",
    ),
    (
        "json",
        "SELECT json_agg(json_build_object('id', id) ORDER BY id) AS agg FROM t WHERE id < 4",
    ),
    (
        "arrays",
        "SELECT id, ARRAY[id, y] AS a, array_length(arr, 1) AS al, array_position(arr, id) AS ap, arr[2] AS second FROM t WHERE id < 4 ORDER BY id",
    ),
    (
        "arrays",
        "SELECT id FROM t WHERE y = ANY (ARRAY[1, 3]) AND NOT ('y' <> ALL (tags)) ORDER BY id",
    ),
    (
        "setops",
        "SELECT id FROM t WHERE y < 2 UNION SELECT t_id FROM u WHERE id < 3 ORDER BY 1",
    ),
    ("setops", "SELECT id FROM t INTERSECT SELECT t_id FROM u ORDER BY 1 LIMIT 5"),
    (
        "setops",
        "SELECT id FROM t EXCEPT SELECT t_id FROM u WHERE amount > 50 ORDER BY 1",
    ),
    ("distinct-order-limit", "SELECT DISTINCT g FROM t ORDER BY g"),
    (
        "distinct-order-limit",
        "SELECT DISTINCT ON (g) g, id, y FROM t ORDER BY g, y DESC, id",
    ),
    (
        "distinct-order-limit",
        "SELECT id, nullif(y, 0) AS ny FROM t ORDER BY ny DESC NULLS FIRST, id LIMIT 5",
    ),
    ("distinct-order-limit", "SELECT id, x FROM t ORDER BY x DESC, id LIMIT 3"),
    (
        "distinct-order-limit",
        "SELECT id, g FROM t WHERE g IS NOT NULL AND id BETWEEN 3 AND 6 ORDER BY id",
    ),
    ("reviewers", "SELECT count(*) AS n FROM t"),
    (
        "reviewers",
        "SELECT g, count(*) AS n, sum(x) AS s, avg(x) AS a, min(d) AS mn, max(d) AS mx FROM t GROUP BY g ORDER BY g",
    ),
    ("reviewers", "SELECT g, ROUND(AVG(x), 2) AS a FROM t GROUP BY g ORDER BY g"),
    ("reviewers", "SELECT ROUND(AVG(x)::numeric, 2) AS a FROM t"),
    (
        "reviewers",
        "SELECT round(stddev_samp(x), 3) AS s, round(var_pop(x), 3) AS v FROM t",
    ),
    (
        "reviewers",
        "SELECT round(sum(amount) / NULLIF(count(*), 0), 2) AS avg_amt FROM u",
    ),
    (
        "reviewers",
        "SELECT status, count(DISTINCT t_id) AS n FROM u GROUP BY status ORDER BY status",
    ),
    (
        "reviewers",
        "SELECT g, count(*) FILTER (WHERE b) AS nb, count(*) FILTER (WHERE NOT b) AS nn FROM t GROUP BY g ORDER BY g",
    ),
    (
        "reviewers",
        "SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY x) AS med, percentile_disc(0.9) WITHIN GROUP (ORDER BY y) AS p90 FROM t",
    ),
    ("reviewers", "SELECT mode() WITHIN GROUP (ORDER BY g) AS m FROM t"),
    (
        "reviewers",
        "SELECT percentile_cont(ARRAY[0.25, 0.5, 0.75]) WITHIN GROUP (ORDER BY x) AS qs FROM t",
    ),
    (
        "reviewers",
        "SELECT corr(x, y) AS c, regr_slope(y, x) AS s, covar_pop(x, y) AS cp FROM t",
    ),
    (
        "reviewers",
        "SELECT bool_and(b) AS ba, bool_or(b) AS bo, every(y > 0) AS e FROM t",
    ),
    ("reviewers", "SELECT string_agg(g, ',' ORDER BY id) AS s FROM t WHERE id < 6"),
    ("reviewers", "SELECT array_agg(DISTINCT g ORDER BY g) AS a FROM t"),
    ("reviewers", "SELECT json_agg(id ORDER BY id) AS j FROM t WHERE id < 4"),
    ("reviewers", "SELECT jsonb_object_agg(g, y) AS o FROM t WHERE id < 4"),
    (
        "reviewers",
        "SELECT g, y, rank() OVER (PARTITION BY g ORDER BY y DESC) AS r FROM t ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT id, row_number() OVER (ORDER BY id) AS rn, dense_rank() OVER (ORDER BY y) AS dr FROM t ORDER BY id",
    ),
    ("reviewers", "SELECT id, ntile(4) OVER (ORDER BY x) AS q FROM t ORDER BY id"),
    (
        "reviewers",
        "SELECT id, lag(x) OVER (ORDER BY id) AS p, lead(x, 2, 0) OVER (ORDER BY id) AS nx FROM t ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT id, first_value(x) OVER w AS f, last_value(x) OVER w AS l FROM t WINDOW w AS (PARTITION BY g ORDER BY id ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING) ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT id, nth_value(x, 2) OVER (ORDER BY id) AS n2 FROM t ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT id, cume_dist() OVER (ORDER BY y) AS cd, percent_rank() OVER (ORDER BY y) AS pr FROM t ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT id, sum(y) OVER (ORDER BY id ROWS 2 PRECEDING) AS r FROM t ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT id, sum(y) OVER (ORDER BY id ROWS BETWEEN 1 PRECEDING AND 1 FOLLOWING) AS r FROM t ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT id, avg(x) OVER (ORDER BY d RANGE BETWEEN INTERVAL '7 days' PRECEDING AND CURRENT ROW) AS r FROM t ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT id, sum(y) OVER (ORDER BY y GROUPS BETWEEN 1 PRECEDING AND CURRENT ROW) AS r FROM t ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT id, sum(y) OVER (ORDER BY id ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW EXCLUDE CURRENT ROW) AS r FROM t ORDER BY id",
    ),
    ("reviewers", "SELECT id, count(*) OVER () AS total FROM t ORDER BY id"),
    (
        "reviewers",
        "SELECT id, sum(x) OVER (PARTITION BY g) / sum(x) OVER () AS share FROM t ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT id, x - avg(x) OVER (PARTITION BY g) AS dev FROM t ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT id FROM t WHERE y > SOME (SELECT y FROM t WHERE g = 'b') ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT id FROM t WHERE y > ALL (SELECT y FROM t WHERE g = 'b') ORDER BY id",
    ),
    ("reviewers", "SELECT id FROM t WHERE y = ANY (ARRAY[2, 5]) ORDER BY id"),
    ("reviewers", "SELECT id FROM t WHERE y <> ALL (ARRAY[2, 5]) ORDER BY id"),
    ("reviewers", "SELECT id FROM t WHERE 'x1' = ANY (tags) ORDER BY id"),
    ("reviewers", "SELECT id FROM t WHERE arr && ARRAY[2] ORDER BY id"),
    ("reviewers", "SELECT id FROM t WHERE arr @> ARRAY[1] ORDER BY id"),
    (
        "reviewers",
        "SELECT id, arr[1] AS a1, arr[1:2] AS sl, array_length(arr, 1) AS al, cardinality(arr) AS c FROM t ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT id, array_to_string(tags, '|') AS s, array_position(tags, 'y') AS p FROM t ORDER BY id",
    ),
    ("reviewers", "SELECT id, string_to_array('a,b,c', ',') AS a FROM t WHERE id = 1"),
    (
        "reviewers",
        "SELECT date_part('year', d) AS yr, EXTRACT(MONTH FROM d) AS mo, extract(dow FROM d) AS dw FROM t ORDER BY id",
    ),
    ("reviewers", "SELECT extract(epoch FROM ts) AS e FROM t ORDER BY id"),
    ("reviewers", "SELECT date_part('epoch', ts) AS e FROM t ORDER BY id"),
    (
        "reviewers",
        "SELECT date_part('dow', d) AS dw, date_part('quarter', d) AS q FROM t ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT date_trunc('month', d)::date AS m, count(*) AS n FROM t GROUP BY 1 ORDER BY 1",
    ),
    (
        "reviewers",
        "SELECT date_trunc('week', ts) AS w, count(*) AS n FROM t GROUP BY 1 ORDER BY 1",
    ),
    (
        "reviewers",
        "SELECT date_trunc('day', ts AT TIME ZONE 'UTC') AS dd FROM t ORDER BY id",
    ),
    ("reviewers", "SELECT ts AT TIME ZONE 'Europe/Berlin' AS local FROM t ORDER BY id"),
    (
        "reviewers",
        "SELECT to_char(d, 'YYYY-MM') AS ym, to_char(x, 'FM999990.00') AS xs FROM t ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT d + INTERVAL '1 day' AS nxt, d - 7 AS wk, d - DATE '2024-01-01' AS days FROM t ORDER BY id",
    ),
    ("reviewers", "SELECT age(d, DATE '2024-01-01') AS ag FROM t ORDER BY id"),
    (
        "reviewers",
        "SELECT ts + iv AS later, iv * 2 AS dbl, justify_hours(iv * 100) AS j FROM t ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT make_date(2024, 2, 29) AS md, make_interval(days => 3) AS mi FROM t WHERE id = 1",
    ),
    (
        "reviewers",
        "SELECT to_date('2024-03-01', 'YYYY-MM-DD') AS td, to_timestamp(0) AS tt, to_number('12.5', '99.9') AS tn FROM t WHERE id = 1",
    ),
    (
        "reviewers",
        "SELECT current_date - d AS since, now() > ts AS past FROM t ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT CURRENT_DATE AS cd, CURRENT_TIMESTAMP > ts AS p, LOCALTIMESTAMP IS NOT NULL AS l FROM t WHERE id = 1",
    ),
    (
        "reviewers",
        "SELECT date_bin(INTERVAL '15 minutes', ts, TIMESTAMPTZ '2024-01-01 00:00+00') AS b FROM t ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT j ->> 'k' AS k, j -> 'n' ->> 'm' AS m, j #>> '{a,0}' AS a0, j #> '{n}' AS n FROM t ORDER BY id",
    ),
    ("reviewers", "SELECT id FROM t WHERE j @> '{\"k\": 2}' ORDER BY id"),
    (
        "reviewers",
        "SELECT id FROM t WHERE j ? 'k' AND j ?| ARRAY['n', 'z'] AND j ?& ARRAY['k', 'a'] ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT jsonb_typeof(j) AS jt, jsonb_array_length(j -> 'a') AS al, jsonb_extract_path_text(j, 'n', 'm') AS m FROM t ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT jsonb_build_object('id', id, 'g', g) AS o, json_build_array(id, g) AS a FROM t ORDER BY id",
    ),
    ("reviewers", "SELECT (j ->> 'k')::int + 1 AS k1 FROM t ORDER BY id"),
    ("reviewers", "SELECT CAST(j ->> 'k' AS integer) AS k FROM t ORDER BY id"),
    (
        "reviewers",
        "SELECT x::numeric(10, 2) AS x2, y::text AS ys, CAST(y AS varchar(5)) AS yv, f::int AS fi FROM t ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT d::timestamp AS dts, '2024-01-01'::date AS lit, '1 day'::interval AS iv1, '{1,2}'::int[] AS ia FROM t WHERE id = 1",
    ),
    (
        "reviewers",
        "SELECT DATE '2024-01-01' AS a, TIMESTAMP '2024-01-01 10:00' AS b, TIME '10:00' AS c, INTERVAL '2 hours' AS e FROM t WHERE id = 1",
    ),
    (
        "reviewers",
        "SELECT TIMESTAMPTZ '2024-01-01 10:00+02' AS a, '10:00'::time AS b FROM t WHERE id = 1",
    ),
    (
        "reviewers",
        "SELECT CAST(ts AS timestamp with time zone) AS a, CAST(ts AS timestamp without time zone) AS b FROM t WHERE id = 1",
    ),
    (
        "reviewers",
        "SELECT CASE WHEN y > 2 THEN 'hi' WHEN y = 2 THEN 'mid' ELSE 'lo' END AS c FROM t ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT CASE g WHEN 'a' THEN 1 WHEN 'b' THEN 2 END AS c FROM t ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT COALESCE(NULLIF(g, 'a'), '-') AS g2, GREATEST(x, y) AS m, LEAST(x, y, 3) AS l FROM t ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT abs(x - 20) AS a, ceil(x) AS c, floor(x) AS fl, trunc(x, 1) AS tr, mod(y, 3) AS m, power(y, 2) AS p, sqrt(x) AS s FROM t ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT ln(x) AS l, log(x) AS lg, log(2, x) AS l2, exp(1) AS e, sign(x - 10) AS sg, pi() AS p FROM t ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT y % 2 AS odd, y ^ 2 AS sq, round(x::numeric, 1) AS r, x / 3 AS div, y / 2 AS idiv FROM t ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT width_bucket(x, 0, 60, 6) AS wb, num_nonnulls(x, NULL, y) AS nn FROM t ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT length(g) AS l, char_length(g) AS cl, octet_length(g) AS ol, upper(g) AS u, lower('AbC') AS lw, initcap('hello world') AS ic FROM t ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT substring(g FROM 1 FOR 1) AS s1, substring('hello' FROM 2) AS s2, substr('hello', 2, 3) AS s3 FROM t WHERE id = 1",
    ),
    (
        "reviewers",
        "SELECT position('l' IN 'hello') AS p, strpos('hello', 'l') AS sp, overlay('hello' PLACING 'XX' FROM 2 FOR 2) AS o FROM t WHERE id = 1",
    ),
    (
        "reviewers",
        "SELECT trim(BOTH ' ' FROM '  x  ') AS a, ltrim('  x') AS b, rtrim('x  ') AS c, btrim('xxyxx', 'x') AS d FROM t WHERE id = 1",
    ),
    (
        "reviewers",
        "SELECT left('hello', 2) AS l, right('hello', 2) AS r, lpad('7', 3, '0') AS lp, rpad('7', 3, '0') AS rp, repeat('ab', 2) AS rp2, reverse('abc') AS rv FROM t WHERE id = 1",
    ),
    (
        "reviewers",
        "SELECT split_part('a.b.c', '.', 2) AS sp, replace('aaa', 'a', 'b') AS rep, translate('abc', 'ab', 'xy') AS tr FROM t WHERE id = 1",
    ),
    (
        "reviewers",
        "SELECT regexp_replace('a1b2', '[0-9]', '', 'g') AS rr, regexp_match('a1b2', '[0-9]') AS rm, 'abc' ~ '^a' AS m1, 'ABC' ~* 'b' AS m2, 'abc' !~ 'z' AS m3 FROM t WHERE id = 1",
    ),
    (
        "reviewers",
        "SELECT format('%s-%s', g, id) AS f, concat(g, id) AS c, concat_ws('/', g, id) AS cw, g || '-' || id AS cc FROM t ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT md5(g) AS h, encode(convert_to(g, 'UTF8'), 'hex') AS hx, starts_with(g, 'a') AS sw FROM t ORDER BY id",
    ),
    ("reviewers", "SELECT id FROM t WHERE g LIKE 'a%' ORDER BY id"),
    (
        "reviewers",
        "SELECT id FROM t WHERE g ILIKE 'A%' AND x BETWEEN 1 AND 30 ORDER BY id",
    ),
    ("reviewers", "SELECT id FROM t WHERE x BETWEEN SYMMETRIC 30 AND 1 ORDER BY id"),
    ("reviewers", "SELECT id FROM t WHERE g NOT LIKE '%b%' ORDER BY id"),
    ("reviewers", "SELECT id FROM t WHERE g LIKE 'a!%' ESCAPE '!' ORDER BY id"),
    ("reviewers", "SELECT id FROM t WHERE g SIMILAR TO '(a|b)' ORDER BY id"),
    (
        "reviewers",
        "SELECT id FROM t WHERE g IN ('a', 'b') AND y NOT IN (1, 2) ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT id FROM t WHERE x IS NOT NULL AND b IS TRUE AND (y > 3 OR g = 'c') ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT id FROM t WHERE b IS NOT FALSE AND g IS DISTINCT FROM 'a' ORDER BY id",
    ),
    ("reviewers", "SELECT id FROM t WHERE NOT b ORDER BY id"),
    ("reviewers", "SELECT id FROM t WHERE (y, id) < (3, 10) ORDER BY id"),
    ("reviewers", "SELECT id, g FROM t ORDER BY g DESC NULLS LAST, id ASC NULLS FIRST"),
    ("reviewers", 'SELECT id, g FROM t ORDER BY g COLLATE "C", id'),
    (
        "reviewers",
        "SELECT g, MAX(y) AS m FROM t GROUP BY g HAVING MAX(y) > 2 ORDER BY g",
    ),
    (
        "reviewers",
        "SELECT g, b, count(*) AS n FROM t GROUP BY ROLLUP (g, b) ORDER BY g, b",
    ),
    (
        "reviewers",
        "SELECT g, b, count(*) AS n FROM t GROUP BY CUBE (g, b) ORDER BY g, b",
    ),
    (
        "reviewers",
        "SELECT g, b, count(*) AS n FROM t GROUP BY GROUPING SETS ((g), (b), ()) ORDER BY g, b",
    ),
    (
        "reviewers",
        "SELECT g, GROUPING(g) AS gg, count(*) AS n FROM t GROUP BY ROLLUP (g) ORDER BY g",
    ),
    ("reviewers", "SELECT DISTINCT ON (g) g, id FROM t ORDER BY g, id DESC"),
    ("reviewers", "SELECT y FROM t UNION SELECT t_id FROM u ORDER BY 1"),
    ("reviewers", "SELECT y FROM t UNION ALL SELECT t_id FROM u ORDER BY 1"),
    ("reviewers", "SELECT y FROM t INTERSECT SELECT t_id FROM u ORDER BY 1"),
    ("reviewers", "SELECT y FROM t EXCEPT SELECT t_id FROM u ORDER BY 1"),
    (
        "reviewers",
        "(SELECT id FROM t ORDER BY id LIMIT 2) UNION ALL (SELECT id FROM u ORDER BY id DESC LIMIT 2)",
    ),
    ("reviewers", "SELECT EXISTS (SELECT 1 FROM t WHERE y > 4) AS e"),
    (
        "reviewers",
        "SELECT id FROM t WHERE EXISTS (SELECT 1 FROM u WHERE u.t_id = t.id AND u.status = 'open') ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT id FROM t WHERE NOT EXISTS (SELECT 1 FROM u WHERE u.t_id = t.id) ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT id, (SELECT count(*) FROM u WHERE u.t_id = t.id) AS nu FROM t ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT id, ARRAY(SELECT u.id FROM u WHERE u.t_id = t.id ORDER BY u.id) AS us FROM t ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT t.id, u.amount FROM t JOIN u ON u.t_id = t.id WHERE t.id < 4 ORDER BY 1, 2",
    ),
    (
        "reviewers",
        "SELECT t.id, u.amount FROM t LEFT JOIN u ON u.t_id = t.id AND u.status = 'void' ORDER BY 1, 2",
    ),
    (
        "reviewers",
        "SELECT t.id, u.id AS uid FROM t FULL OUTER JOIN u ON u.t_id = t.id WHERE t.id IS NULL OR u.id IS NULL ORDER BY 1, 2",
    ),
    (
        "reviewers",
        "SELECT t.id, u.id AS uid FROM t RIGHT JOIN u ON u.t_id = t.id WHERE u.id < 5 ORDER BY 2",
    ),
    (
        "reviewers",
        "SELECT a.id, b.id AS bid FROM t AS a JOIN t AS b ON b.y = a.y AND b.id > a.id WHERE a.id < 5 ORDER BY 1, 2",
    ),
    ("reviewers", "SELECT a.id FROM t a CROSS JOIN (SELECT 1 AS one) o ORDER BY 1"),
    ("reviewers", "SELECT id FROM t JOIN u USING (id) ORDER BY id"),
    (
        "reviewers",
        "SELECT t.id, l.mx FROM t CROSS JOIN LATERAL (SELECT max(amount) AS mx FROM u WHERE u.t_id = t.id) l ORDER BY 1",
    ),
    (
        "reviewers",
        "SELECT t.id, l.mx FROM t LEFT JOIN LATERAL (SELECT amount AS mx FROM u WHERE u.t_id = t.id ORDER BY amount DESC LIMIT 1) l ON true ORDER BY 1",
    ),
    (
        "reviewers",
        "WITH s AS (SELECT t_id, sum(amount) AS total FROM u GROUP BY t_id) SELECT t.id, s.total FROM t JOIN s ON s.t_id = t.id ORDER BY 1",
    ),
    (
        "reviewers",
        "WITH a AS (SELECT id FROM t WHERE y > 2), b AS (SELECT id FROM a WHERE id < 20) SELECT count(*) AS n FROM b",
    ),
    (
        "reviewers",
        "WITH m AS MATERIALIZED (SELECT id FROM t) SELECT count(*) AS n FROM m",
    ),
    (
        "reviewers",
        "WITH m AS NOT MATERIALIZED (SELECT id FROM t) SELECT count(*) AS n FROM m",
    ),
    (
        "reviewers",
        "WITH c(a, b) AS (SELECT id, y FROM t) SELECT a, b FROM c ORDER BY a",
    ),
    (
        "reviewers",
        "SELECT v.a, v.b FROM (VALUES (1, 'x'), (2, 'y')) AS v(a, b) ORDER BY 1",
    ),
    ("reviewers", "SELECT s.a FROM (SELECT id AS a FROM t) s WHERE s.a < 3 ORDER BY 1"),
    ("reviewers", 'SELECT x AS "Amount", g AS "Group Name" FROM t ORDER BY id'),
    ("reviewers", 'SELECT "id", "g" FROM "t" ORDER BY "id"'),
    ("reviewers", "SELECT T.ID FROM T ORDER BY T.ID"),
    (
        "reviewers",
        "SELECT id, 1e3 AS a, .5 AS b, 5. AS c, 1.5e-3 AS d, 100000000000000000000 AS big FROM t WHERE id = 1",
    ),
    (
        "reviewers",
        "SELECT 'it''s' AS a, 'multi\nline' AS b, 'tab\there' AS c, 'back\\slash' AS d, 'üñî©ødé 😀' AS e FROM t WHERE id = 1",
    ),
    ("reviewers", "SELECT $$dollar 'quoted'$$ AS a, $q$x$q$ AS b FROM t WHERE id = 1"),
    ("reviewers", "SELECT E'no backslash' AS a, e'it''s' AS b FROM t WHERE id = 1"),
    ("reviewers", "SELECT x'1F' AS a, B'101' AS b FROM t WHERE id = 1"),
    (
        "reviewers",
        "SELECT NULL AS n, TRUE AS t1, FALSE AS f1, NULL::int AS ni FROM t WHERE id = 1",
    ),
    ("reviewers", "SELECT id FROM t WHERE id = 1 -- trailing comment"),
    ("reviewers", "SELECT /* c */ id FROM t WHERE id = 1;"),
    ("reviewers", "SELECT id FROM t ORDER BY id LIMIT 3"),
    ("reviewers", "SELECT id FROM t ORDER BY id LIMIT ALL"),
    (
        "reviewers",
        "SELECT count(*) AS n, count(x) AS nx, count(DISTINCT (g, b)) AS nd FROM t",
    ),
    (
        "reviewers",
        "SELECT sum(CASE WHEN b THEN 1 ELSE 0 END) AS nb, avg(y::float) AS ay FROM t",
    ),
    (
        "reviewers",
        "SELECT g, round(100.0 * count(*) / sum(count(*)) OVER (), 1) AS pct FROM t GROUP BY g ORDER BY g",
    ),
    (
        "reviewers",
        "SELECT g, sum(x) AS s, rank() OVER (ORDER BY sum(x) DESC) AS r FROM t GROUP BY g ORDER BY r",
    ),
    (
        "reviewers",
        "SELECT date_trunc('month', created) AS m, status, sum(amount) AS s FROM u GROUP BY 1, 2 ORDER BY 1, 2",
    ),
    (
        "reviewers",
        "SELECT to_char(date_trunc('month', created), 'YYYY-MM') AS m, count(*) FILTER (WHERE status = 'open') AS o FROM u GROUP BY 1 ORDER BY 1",
    ),
    (
        "reviewers",
        "SELECT extract(year FROM created)::int AS y, extract(week FROM created) AS w, count(*) AS n FROM u GROUP BY 1, 2 ORDER BY 1, 2",
    ),
    (
        "reviewers",
        "SELECT created::date - lag(created::date) OVER (ORDER BY created) AS gap FROM u ORDER BY created",
    ),
    (
        "reviewers",
        "SELECT t_id, sum(amount) OVER (PARTITION BY t_id ORDER BY created ROWS UNBOUNDED PRECEDING) AS cum FROM u ORDER BY t_id, created",
    ),
    (
        "reviewers",
        "SELECT id, amount, amount - lag(amount) OVER (ORDER BY id) AS delta, round((amount / NULLIF(lag(amount) OVER (ORDER BY id), 0) - 1) * 100, 1) AS pct FROM u ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT status, percentile_cont(0.5) WITHIN GROUP (ORDER BY amount) AS med FROM u GROUP BY status ORDER BY status",
    ),
    (
        "reviewers",
        "SELECT id FROM u WHERE created >= DATE '2024-02-01' AND created < DATE '2024-03-01' ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT id FROM u WHERE created BETWEEN '2024-02-01' AND '2024-02-10' ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT id FROM u WHERE created > now() - INTERVAL '30 days' ORDER BY id",
    ),
    ("reviewers", "SELECT id FROM u WHERE created > current_date - 30 ORDER BY id"),
    (
        "reviewers",
        "SELECT id FROM u WHERE status = ANY ('{open,void}'::text[]) ORDER BY id",
    ),
    ("reviewers", "SELECT count(*) AS n FROM u WHERE amount::int % 2 = 0"),
    ("reviewers", "SELECT id, amount::money AS m FROM u ORDER BY id"),
    ("reviewers", "SELECT id, round(amount, 0)::bigint AS r FROM u ORDER BY id"),
    ("reviewers", "SELECT id, to_char(amount, 'FM9,999.00') AS f FROM u ORDER BY id"),
    (
        "reviewers",
        "SELECT g, string_agg(DISTINCT g, ', ') AS gs FROM t GROUP BY g ORDER BY g",
    ),
    ("reviewers", "SELECT id, x FROM t WHERE x > (SELECT avg(x) FROM t) ORDER BY id"),
    (
        "reviewers",
        "SELECT id FROM t WHERE id IN (SELECT t_id FROM u WHERE amount > 50) ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT id FROM t WHERE (id, y) IN (SELECT t_id, 1 FROM u) ORDER BY id",
    ),
    ("reviewers", "SELECT id, y FROM t WHERE y = (SELECT max(y) FROM t) ORDER BY id"),
    ("reviewers", "SELECT max(x) - min(x) AS rng, max(d) - min(d) AS span FROM t"),
    ("reviewers", "SELECT count(*) AS n FROM t, u"),
    ("reviewers", "SELECT id::text || ':' || g AS label FROM t ORDER BY id"),
    (
        "reviewers",
        "SELECT id, iv::text AS ivs, extract(minute FROM iv) AS m FROM t ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT id, NOT (y > 3) AS small, (y > 3) = b AS eq FROM t ORDER BY id",
    ),
    ("reviewers", "SELECT id, factorial(y) AS f FROM t ORDER BY id"),
    ("reviewers", "SELECT id, x::float8 / NULLIF(y, 0) AS r FROM t ORDER BY id"),
    ("reviewers", "SELECT id, b::int AS bi, (y > 2)::int AS gi FROM t ORDER BY id"),
    (
        "reviewers",
        "SELECT id FROM t WHERE g = 'a' AND (b OR y = 3) AND NOT (x < 5) ORDER BY id",
    ),
    ("reviewers", "SELECT id, coalesce(x, 0) + coalesce(y, 0) AS s FROM t ORDER BY id"),
    ("reviewers", "SELECT id, nullif(y, 0) AS n FROM t ORDER BY id"),
    ("reviewers", "SELECT id, greatest(d, DATE '2024-02-01') AS gd FROM t ORDER BY id"),
    (
        "reviewers",
        "SELECT id, d::text AS ds, to_char(ts, 'HH24:MI') AS hm, ts::date AS td FROM t ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT id, extract(hour FROM ts AT TIME ZONE 'UTC') AS h FROM t ORDER BY id",
    ),
    ("reviewers", "SELECT id, date_part('hour', ts) AS h FROM t ORDER BY id"),
    (
        "reviewers",
        "SELECT id, EXTRACT(ISODOW FROM d) AS idw, EXTRACT(DOY FROM d) AS doy, EXTRACT(CENTURY FROM d) AS c FROM t ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT id, jsonb_path_query_first(j, '$.a[0]') AS p FROM t ORDER BY id",
    ),
    ("reviewers", "SELECT id, j -> 'a' -> 0 AS a0, j['k'] AS ks FROM t ORDER BY id"),
    (
        "reviewers",
        "SELECT id, j - 'k' AS rm, j || '{\"z\": 1}'::jsonb AS mg FROM t ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT id, to_jsonb(g) AS jg, jsonb_pretty(j) AS pp FROM t WHERE id = 1",
    ),
    ("reviewers", "SELECT id, (j ->> 'k')::numeric / 2 AS h FROM t ORDER BY id"),
    (
        "reviewers",
        "SELECT id, ARRAY[1, 2, 3] AS a, ARRAY['x', g] AS b, '{}'::int[] AS e FROM t WHERE id = 1",
    ),
    (
        "reviewers",
        "SELECT id, array_remove(arr, 1) AS r, array_append(arr, 9) AS ap, arr || 7 AS c FROM t ORDER BY id",
    ),
    ("reviewers", "SELECT id, g FROM t WHERE g IS NULL OR g = '' ORDER BY id"),
    ("reviewers", "SELECT id FROM t WHERE x::text LIKE '1%' ORDER BY id"),
    ("reviewers", "SELECT ROW(id, g) AS r FROM t WHERE id = 1"),
    ("reviewers", "SELECT (1, 2) = (1, 2) AS e FROM t WHERE id = 1"),
    (
        "reviewers",
        "SELECT id, y IS NULL AS n, y ISNULL AS n2, y NOTNULL AS n3 FROM t ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT id, g::char(3) AS c3, 'x'::\"char\" AS ch FROM t WHERE id = 1",
    ),
    ("reviewers", "SELECT id FROM t TABLESAMPLE SYSTEM (100) ORDER BY id"),
    ("reviewers", "SELECT id, random() >= 0 AS r FROM t ORDER BY id"),
    ("reviewers", "SELECT id, gen_random_uuid() IS NOT NULL AS u FROM t WHERE id = 1"),
    ("reviewers", "SELECT count(*) AS n FROM (SELECT DISTINCT g, b FROM t) s"),
    (
        "reviewers",
        "SELECT g FROM t GROUP BY g HAVING count(*) > 5 ORDER BY count(*) DESC, g",
    ),
    ("reviewers", "SELECT id, interval '1 day' * y AS iv2 FROM t ORDER BY id"),
    ("reviewers", "SELECT id, INTERVAL '1' DAY AS i1 FROM t WHERE id = 1"),
    (
        "reviewers",
        "SELECT id, d + y AS dy, d + make_interval(months => y) AS dm FROM t ORDER BY id",
    ),
    ("reviewers", "SELECT id, date_trunc('quarter', d) AS q FROM t ORDER BY id"),
    (
        "reviewers",
        "SELECT id, to_char(d, 'Day') AS dn, to_char(d, 'Mon') AS mn, to_char(d, 'IYYY-IW') AS iw FROM t ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT id, d IN (DATE '2024-01-04', DATE '2024-01-07') AS hit FROM t ORDER BY id",
    ),
    ("reviewers", "SELECT id, ts::time AS tm, ts::date AS dt FROM t ORDER BY id"),
    ("reviewers", "SELECT id, (ts AT TIME ZONE 'UTC')::date AS dt FROM t ORDER BY id"),
    ("reviewers", "SELECT id, timezone('UTC', ts) AS tz FROM t ORDER BY id"),
    ("reviewers", "SELECT id, isfinite(d) AS f FROM t ORDER BY id"),
    (
        "reviewers",
        "SELECT id, x::int AS xi, x::bigint AS xb, x::real AS xr, x::double precision AS xd, x::decimal(6, 1) AS xdec FROM t ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT id, cast(x AS int) AS ci, cast(d AS text) AS ct FROM t ORDER BY id",
    ),
    ("reviewers", "SELECT id, y::boolean AS yb FROM t ORDER BY id"),
    ("reviewers", "SELECT id, g::bytea AS gb FROM t WHERE id = 1"),
    ("reviewers", "SELECT id, length(g::bytea) AS gl FROM t ORDER BY id"),
    (
        "reviewers",
        "SELECT g, avg(x) FILTER (WHERE y > 1) AS a, sum(y) FILTER (WHERE b) AS s FROM t GROUP BY g ORDER BY g",
    ),
    (
        "reviewers",
        "SELECT g, array_agg(id ORDER BY id DESC) FILTER (WHERE y > 3) AS ids FROM t GROUP BY g ORDER BY g",
    ),
    (
        "reviewers",
        "SELECT max(x) OVER (PARTITION BY g ORDER BY id) AS m, g, id FROM t ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT g, y, sum(x) OVER (PARTITION BY g, y) AS s FROM t ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT id, avg(x) OVER (ORDER BY id ROWS BETWEEN 2 PRECEDING AND CURRENT ROW) AS ma3 FROM t ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT id, avg(x) OVER (ORDER BY id ROWS BETWEEN CURRENT ROW AND 2 FOLLOWING) AS fwd FROM t ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT id, count(*) OVER (ORDER BY y RANGE BETWEEN 1 PRECEDING AND 1 FOLLOWING) AS c FROM t ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT id, sum(y) OVER (ORDER BY id RANGE UNBOUNDED PRECEDING) AS c FROM t ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT id, sum(y) OVER (ORDER BY id ROWS CURRENT ROW) AS c FROM t ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT id, sum(y) OVER (ORDER BY id ROWS BETWEEN 3 PRECEDING AND 1 PRECEDING) AS c FROM t ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT id, sum(y) OVER (ORDER BY y GROUPS 1 PRECEDING EXCLUDE TIES) AS c FROM t ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT id, sum(y) OVER (ORDER BY y ROWS UNBOUNDED PRECEDING EXCLUDE GROUP) AS c FROM t ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT id, sum(y) OVER (ORDER BY id ROWS UNBOUNDED PRECEDING EXCLUDE NO OTHERS) AS c FROM t ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT id FROM t WHERE y < ANY (SELECT y FROM t WHERE g = 'c') ORDER BY id",
    ),
    ("reviewers", "SELECT id FROM t WHERE y >= ALL (ARRAY[1, 2]) ORDER BY id"),
    ("reviewers", "SELECT id FROM t WHERE g LIKE ANY (ARRAY['a%', 'b%']) ORDER BY id"),
    ("reviewers", "SELECT id FROM t WHERE g ILIKE ALL (ARRAY['%', 'a%']) ORDER BY id"),
    (
        "reviewers",
        "SELECT id, y FROM t WHERE y IN (SELECT DISTINCT y FROM t WHERE g = 'a') ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT g, round(avg(y), 2) AS a, round(stddev(y), 2) AS s, round(variance(x), 2) AS v FROM t GROUP BY g ORDER BY g",
    ),
    ("reviewers", "SELECT round(avg(x), 2)::float AS a FROM t"),
    (
        "reviewers",
        "SELECT round(sum(x) * 100.0 / (SELECT sum(x) FROM t), 2) AS pct FROM t WHERE g = 'a'",
    ),
    ("reviewers", "SELECT round(cast(avg(x) AS numeric), 2) AS a FROM t"),
    ("reviewers", "SELECT trunc(avg(x), 1) AS a FROM t"),
    ("reviewers", "SELECT ceil(avg(x)) AS a, floor(avg(y)) AS b FROM t"),
    ("reviewers", "SELECT round(avg(f)::numeric, 3) AS a FROM t"),
    (
        "reviewers",
        "SELECT round(percentile_cont(0.5) WITHIN GROUP (ORDER BY x)::numeric, 2) AS m FROM t",
    ),
    (
        "reviewers",
        "SELECT g, count(*) AS n FROM t GROUP BY g ORDER BY n DESC, g LIMIT 2",
    ),
    ("reviewers", "SELECT g, count(*) AS n FROM t GROUP BY 1 ORDER BY 2 DESC, 1"),
    ("reviewers", "SELECT g AS grp, count(*) AS n FROM t GROUP BY grp ORDER BY grp"),
    ("reviewers", "SELECT id, lower(g) = 'a' AS isa FROM t ORDER BY id"),
    (
        "reviewers",
        "SELECT id, LOWER(g) AS lg, Upper(g) AS ug, CoalEsce(g, 'z') AS cg FROM t ORDER BY id",
    ),
    ("reviewers", "SELECT id, now() - ts AS ago FROM t ORDER BY id"),
    ("reviewers", "SELECT id, clock_timestamp() > ts AS p FROM t ORDER BY id"),
    ("reviewers", "SELECT id, statement_timestamp() > ts AS p FROM t ORDER BY id"),
    (
        "reviewers",
        "SELECT id, extract(epoch FROM now() - ts) / 3600 AS hours FROM t ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT id, justify_interval(now() - ts) IS NOT NULL AS j FROM t ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT g, jsonb_agg(jsonb_build_object('id', id) ORDER BY id) AS items FROM t GROUP BY g ORDER BY g",
    ),
    ("reviewers", "SELECT jsonb_agg(DISTINCT g) AS gs FROM t"),
    (
        "reviewers",
        "SELECT id, j->>'k' AS k FROM t WHERE (j->>'k')::int > 35 ORDER BY id",
    ),
    ("reviewers", "SELECT id, j#>>'{n,m}' AS m FROM t ORDER BY id"),
    ("reviewers", "SELECT id FROM t WHERE j->'n'->>'m' = '1' ORDER BY id"),
    ("reviewers", "SELECT id FROM t WHERE j @@ '$.k > 38' ORDER BY id"),
    (
        "reviewers",
        "SELECT id, regexp_split_to_array('a b c', ' ') AS a FROM t WHERE id = 1",
    ),
    (
        "reviewers",
        "SELECT id, substring('abc123' FROM '[0-9]+') AS d FROM t WHERE id = 1",
    ),
    ("reviewers", "SELECT id, 'abc' SIMILAR TO 'a%' AS s FROM t WHERE id = 1"),
    (
        "reviewers",
        "SELECT id, to_tsvector('english', 'the quick fox') @@ to_tsquery('english', 'fox') AS m FROM t WHERE id = 1",
    ),
    ("reviewers", "SELECT id, g < 'b' COLLATE \"C\" AS lt FROM t ORDER BY id"),
    ("reviewers", "SELECT id, g IN (SELECT status FROM u) AS x FROM t ORDER BY id"),
    (
        "reviewers",
        "SELECT id, CASE WHEN EXISTS (SELECT 1 FROM u WHERE u.t_id = t.id) THEN 1 ELSE 0 END AS has FROM t ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT id, (CASE WHEN y = 0 THEN NULL ELSE x / y END)::numeric(10, 3) AS r FROM t ORDER BY id",
    ),
    ("reviewers", "SELECT 1 AS one"),
    ("reviewers", "SELECT 1 + 1 AS two, 'a' AS s, 2.5 * 2 AS f"),
    ("reviewers", "SELECT now()::date AS today"),
    ("reviewers", "SELECT CURRENT_DATE - INTERVAL '1 month' AS lm"),
    ("reviewers", "SELECT date_trunc('month', CURRENT_DATE) - INTERVAL '1 day' AS eom"),
    (
        "reviewers",
        "SELECT extract(year FROM age(DATE '2024-01-01', DATE '2000-06-15')) AS yrs",
    ),
    ("reviewers", "SELECT array_length(ARRAY[1, 2, 3], 1) AS l"),
    ("reviewers", "SELECT 'a' || 'b' AS ab, 'x' || NULL AS xn"),
    (
        "reviewers",
        "SELECT 5 / 2 AS i, 5 / 2.0 AS d, 5 % 3 AS m, 2 ^ 10 AS p, -5 AS n, abs(-5) AS a",
    ),
    ("reviewers", "SELECT 10 BETWEEN 1 AND 20 AS b"),
    ("reviewers", "SELECT NULL IS NULL AS a, NULL = NULL AS b"),
    ("reviewers", "SELECT 'abc' LIKE 'a_c' AS m"),
    ("reviewers", "SELECT CAST('42' AS int) + 1 AS n"),
    ("reviewers", "SELECT '2024-01-31'::date + INTERVAL '1 month' AS d"),
    (
        "reviewers",
        "SELECT id FROM t WHERE id = ANY ((SELECT array_agg(t_id) FROM u WHERE amount > 90)::int[]) ORDER BY id",
    ),
    ("reviewers", "SELECT id FROM t WHERE id % 10 = 0 ORDER BY id DESC"),
    (
        "reviewers",
        "SELECT id FROM t WHERE g = ANY (string_to_array('a,c', ',')) ORDER BY id",
    ),
    ("reviewers", "SELECT DISTINCT ON (g, b) g, b, id FROM t ORDER BY g, b, id"),
    ("reviewers", "SELECT g, b FROM t GROUP BY g, b ORDER BY g, b"),
    ("reviewers", "SELECT count(1) AS n FROM t"),
    ("reviewers", "SELECT sum(amount) AS s FROM u WHERE status <> 'void'"),
    ("reviewers", "SELECT sum(amount) AS s FROM u WHERE status != 'void'"),
    (
        "reviewers",
        "SELECT u.status, count(*) AS n, round(avg(u.amount), 2) AS a, min(t.d) AS first_d FROM u JOIN t ON t.id = u.t_id GROUP BY u.status ORDER BY 1",
    ),
    (
        "reviewers",
        "SELECT t.g, u.status, sum(u.amount) AS s FROM t JOIN u ON u.t_id = t.id GROUP BY t.g, u.status HAVING sum(u.amount) > 100 ORDER BY 1, 2",
    ),
    (
        "reviewers",
        "SELECT t.g, count(u.id) AS n FROM t LEFT JOIN u ON u.t_id = t.id GROUP BY t.g ORDER BY t.g",
    ),
    (
        "reviewers",
        "WITH ranked AS (SELECT t_id, amount, row_number() OVER (PARTITION BY t_id ORDER BY amount DESC) AS rn FROM u) SELECT t_id, amount FROM ranked WHERE rn = 1 ORDER BY t_id",
    ),
    (
        "reviewers",
        "WITH monthly AS (SELECT date_trunc('month', created) AS m, sum(amount) AS s FROM u GROUP BY 1) SELECT m, s, s - lag(s) OVER (ORDER BY m) AS diff, round(100 * (s / lag(s) OVER (ORDER BY m) - 1), 1) AS growth FROM monthly ORDER BY m",
    ),
    (
        "reviewers",
        "WITH x AS (SELECT g, count(*) AS n FROM t GROUP BY g), y AS (SELECT sum(n) AS total FROM x) SELECT x.g, x.n, round(x.n * 100.0 / y.total, 1) AS pct FROM x CROSS JOIN y ORDER BY x.g",
    ),
    ("reviewers", "SELECT y FROM t INTERSECT ALL SELECT y FROM t ORDER BY 1"),
    ("reviewers", "SELECT y FROM t EXCEPT ALL SELECT t_id FROM u ORDER BY 1"),
    (
        "reviewers",
        "SELECT id, sum(y) OVER w AS s FROM t WINDOW w AS (ORDER BY id ROWS BETWEEN 1 PRECEDING AND 1 FOLLOWING EXCLUDE CURRENT ROW) ORDER BY id",
    ),
    ("reviewers", "SELECT id, log(3, x) AS l FROM t ORDER BY id"),
    ("reviewers", "SELECT id, array_length(arr, 2) AS l FROM t ORDER BY id"),
    ("reviewers", "SELECT id FROM t WHERE id = 1 /*+ hint */"),
    ("reviewers", "SELECT /*+ SeqScan(t) */ id FROM t WHERE id = 1"),
    ("reviewers", "SELECT id, decode(g, 'escape') AS i FROM t ORDER BY id"),
    (
        "reviewers",
        "SELECT id, g FROM t WHERE g = 'a' AND id IN (1, 4) ORDER BY id NULLS FIRST",
    ),
    (
        "reviewers",
        "SELECT g, count(*) AS n FROM t GROUP BY DISTINCT ROLLUP (g), ROLLUP (g) ORDER BY g",
    ),
    (
        "reviewers",
        "SELECT id, array_agg(y ORDER BY y) AS a FROM t GROUP BY id ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT id, json_extract_path_text(j::json, 'k') AS v FROM t WHERE id = 1",
    ),
    ("reviewers", "SELECT id, j->>'k' = '1' AS v FROM t ORDER BY id"),
    ("reviewers", "SELECT id, x::numeric AS n, x::NUMERIC(5) AS n5 FROM t ORDER BY id"),
    (
        "reviewers",
        "SELECT id, y::smallint AS s, y::int2 AS s2, y::int8 AS i8, y::float4 AS f4 FROM t ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT id, d::timestamptz AS a, ts::timestamp(0) AS b, ts::timestamptz(3) AS c FROM t WHERE id = 1",
    ),
    ("reviewers", "SELECT id, '1 day'::interval day AS a FROM t WHERE id = 1"),
    ("reviewers", "SELECT id, x::text::numeric AS n FROM t ORDER BY id"),
    ("reviewers", "SELECT id, b::text AS bt, 'yes'::boolean AS yb FROM t ORDER BY id"),
    (
        "reviewers",
        "SELECT id, ARRAY[y]::text[] AS a, '{a,b}'::varchar[] AS v FROM t WHERE id = 1",
    ),
    ("reviewers", "SELECT id, y::bit(4) AS bits, y::oid AS o FROM t WHERE id = 1"),
    ("reviewers", "SELECT id, jsonb_set(j, '{k}', '0') AS s FROM t WHERE id = 1"),
    ("reviewers", "SELECT id, j ->> 0 AS a FROM t WHERE id = 1"),
    ("reviewers", "SELECT id, (j -> 'a') ->> 1 AS a1 FROM t ORDER BY id"),
    ("reviewers", "SELECT id, j #> ARRAY['n', 'm'] AS p FROM t ORDER BY id"),
    ("reviewers", "SELECT id, x * 1.0 / NULLIF(y, 0) AS r FROM t ORDER BY id"),
    (
        "reviewers",
        "SELECT id, y::numeric / 3 AS r, round(y::numeric / 3, 4) AS rr FROM t ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT count(*) FILTER (WHERE x > 10)::float / count(*) AS ratio FROM t",
    ),
    ("reviewers", "SELECT id, (x > 10 AND y < 3) OR b AS c FROM t ORDER BY id"),
    (
        "reviewers",
        "SELECT id, NOT b AND y > 2 AS c, NOT (b AND y > 2) AS d FROM t ORDER BY id",
    ),
    ("reviewers", "SELECT id, y = 1 IS TRUE AS c FROM t ORDER BY id"),
    (
        "reviewers",
        "SELECT id, - y ^ 2 AS a, (-y) ^ 2 AS b, -y * 2 AS c FROM t ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT id, 2 ^ 3 ^ 2 AS a, 2 * 3 % 4 AS b, 10 - 2 - 3 AS c, 2 ^ -1 AS d FROM t WHERE id = 1",
    ),
    (
        "reviewers",
        "SELECT id, y || 'x' || y AS a, 'a' || 1 + 2 AS b FROM t WHERE id = 1",
    ),
    ("reviewers", "SELECT id, x BETWEEN 1 AND 5 = b AS c FROM t ORDER BY id"),
    ("reviewers", "SELECT id, y IN (1, 2) = b AS c FROM t ORDER BY id"),
    ("reviewers", "SELECT id, g LIKE 'a' = b AS c FROM t ORDER BY id"),
    ("reviewers", "SELECT id, y IS NULL = b AS c FROM t ORDER BY id"),
    ("reviewers", "SELECT id, j #- '{k}' AS a FROM t WHERE id = 1"),
    (
        "reviewers",
        "SELECT id, arr <@ ARRAY[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40] AS a FROM t ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT id, g ~~ 'a%' AS a, g ~~* 'A%' AS b, g !~~ 'a%' AS c FROM t ORDER BY id",
    ),
    ("reviewers", "SELECT id, ts - INTERVAL '1 hour' * y AS a FROM t ORDER BY id"),
    ("reviewers", "SELECT id, (d + TIME '10:00') AS a FROM t ORDER BY id"),
    ("reviewers", "SELECT id, d - INTERVAL '1 month' AS a FROM t ORDER BY id"),
    (
        "reviewers",
        "SELECT id, EXTRACT(EPOCH FROM INTERVAL '1 day') AS a FROM t WHERE id = 1",
    ),
    (
        "reviewers",
        "SELECT id, ts AT TIME ZONE 'UTC' AT TIME ZONE 'Asia/Tokyo' AS a FROM t ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT id, date_trunc('month', ts, 'Asia/Tokyo') AS a FROM t ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT id, to_char(ts AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS') AS a FROM t ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT id, to_char(d, 'DD.MM.YYYY') AS a, to_char(1234.5, '9G999D99') AS b FROM t WHERE id = 1",
    ),
    (
        "reviewers",
        "SELECT id, overlaps_ok FROM (SELECT id, (d, d + 1) OVERLAPS (DATE '2024-01-05', DATE '2024-01-10') AS overlaps_ok FROM t) s ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT id, CASE WHEN y BETWEEN 0 AND 2 THEN 'low' WHEN y BETWEEN 3 AND 4 THEN 'mid' ELSE 'high' END AS band, count(*) OVER (PARTITION BY CASE WHEN y < 3 THEN 1 ELSE 2 END) AS n FROM t ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT id, sum(y) OVER (PARTITION BY g ORDER BY d RANGE BETWEEN INTERVAL '10 days' PRECEDING AND INTERVAL '1 day' FOLLOWING) AS s FROM t ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT id, avg(y) OVER (ORDER BY ts RANGE BETWEEN '1 day'::interval PRECEDING AND CURRENT ROW) AS s FROM t ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT g, sum(y) AS s, sum(sum(y)) OVER (ORDER BY g) AS running FROM t GROUP BY g ORDER BY g",
    ),
    (
        "reviewers",
        "SELECT g, count(*) AS n, count(*) * 100 / sum(count(*)) OVER () AS pct FROM t GROUP BY g ORDER BY g",
    ),
    (
        "reviewers",
        "SELECT id, max(y) OVER (PARTITION BY g) = y AS is_max FROM t ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT id, y, count(*) OVER (PARTITION BY y ORDER BY id ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) AS n FROM t ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT id, array_agg(y) OVER (ORDER BY id ROWS 2 PRECEDING) AS w FROM t ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT id, string_agg(g, '') OVER (ORDER BY id ROWS BETWEEN 2 PRECEDING AND CURRENT ROW) AS w FROM t ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT DISTINCT g, count(*) OVER (PARTITION BY g) AS n FROM t ORDER BY g",
    ),
    ("reviewers", "SELECT g FROM t GROUP BY g HAVING bool_and(y >= 0) ORDER BY g"),
    (
        "reviewers",
        "SELECT g, b, count(*) AS n, GROUPING(g, b) AS gi FROM t GROUP BY GROUPING SETS ((g, b), g, ()) ORDER BY g, b, gi",
    ),
    (
        "reviewers",
        "SELECT g, avg(x) AS a FROM t GROUP BY g HAVING avg(x) > (SELECT avg(x) FROM t) ORDER BY g",
    ),
    (
        "reviewers",
        "SELECT id, x FROM t WHERE x = (SELECT max(x) FROM t AS t2 WHERE t2.g = t.g) ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT id FROM t AS outer_t WHERE NOT EXISTS (SELECT 1 FROM t AS i WHERE i.g = outer_t.g AND i.id < outer_t.id) ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT x.g, x.n FROM (SELECT g, count(*) AS n FROM t GROUP BY g) AS x WHERE x.n > 1 ORDER BY x.g",
    ),
    (
        "reviewers",
        "SELECT a.g, b.status FROM (SELECT DISTINCT g FROM t) a CROSS JOIN (SELECT DISTINCT status FROM u) b ORDER BY 1, 2",
    ),
    ("reviewers", "SELECT id FROM t NATURAL JOIN u ORDER BY id"),
    (
        "reviewers",
        "SELECT t.id FROM t INNER JOIN u ON (u.t_id = t.id) WHERE u.amount > 95 ORDER BY 1",
    ),
    (
        "reviewers",
        "SELECT t.id, u.id AS uid FROM t LEFT OUTER JOIN u ON u.t_id = t.id AND u.amount > 99 WHERE t.id < 3 ORDER BY 1, 2",
    ),
    (
        "reviewers",
        "SELECT t.id FROM t JOIN u ON u.t_id = t.id JOIN t AS t2 ON t2.id = u.t_id WHERE t.id = 2 ORDER BY 1",
    ),
    (
        "reviewers",
        "SELECT count(*) AS n FROM t JOIN u ON u.t_id = t.id AND u.created BETWEEN t.d AND t.d + 30",
    ),
    (
        "reviewers",
        "SELECT (SELECT max(amount) FROM u) AS mx, (SELECT min(amount) FROM u) AS mn",
    ),
    (
        "reviewers",
        "SELECT id, (SELECT u.status FROM u WHERE u.t_id = t.id ORDER BY u.id LIMIT 1) AS st FROM t ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT id FROM t WHERE id IN (SELECT t_id FROM u GROUP BY t_id HAVING count(*) > 2) ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT id FROM t WHERE y NOT IN (SELECT y FROM t WHERE y IS NOT NULL AND g = 'a') ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT id FROM t WHERE (g, y) = ANY (SELECT g, y FROM t WHERE id < 3) ORDER BY id",
    ),
    (
        "reviewers",
        "WITH a AS (SELECT g, sum(x) AS s FROM t GROUP BY g) SELECT g, s, s / (SELECT sum(s) FROM a) AS share FROM a ORDER BY g",
    ),
    (
        "reviewers",
        "WITH a AS (SELECT id, y FROM t), b AS (SELECT y, count(*) AS n FROM a GROUP BY y) SELECT a.id, b.n FROM a JOIN b USING (y) ORDER BY a.id",
    ),
    (
        "reviewers",
        "WITH x AS (SELECT 1 AS one) SELECT one FROM x UNION ALL SELECT 2 ORDER BY 1",
    ),
    ("reviewers", "SELECT 'O''Brien' AS n, 'a''''b' AS m, '' AS e, ' ' AS s"),
    ("reviewers", "SELECT '\\' AS a, '\\\\' AS b, 'a\\nb' AS c, '\\''' AS d"),
    ("reviewers", "SELECT 'line1\nline2' AS ml, 'tab\tx' AS tb"),
    ("reviewers", "SELECT 'Ж' AS cyr, '中文' AS zh, '🎉' AS em, 'é' AS e1, 'é' AS e2"),
    ("reviewers", 'SELECT "x y" FROM (SELECT 1 AS "x y") s'),
    ("reviewers", 'SELECT "a""b" FROM (SELECT 1 AS "a""b") s'),
    ("reviewers", 'SELECT "Select" FROM (SELECT 1 AS "Select") s'),
    ("reviewers", 'SELECT "ÄÖ" FROM (SELECT 1 AS "ÄÖ") s'),
    ("reviewers", "SELECT äö FROM (SELECT 1 AS äö) s"),
    ("reviewers", "SELECT a$b FROM (SELECT 1 AS a$b) s"),
    ("reviewers", "SELECT _x FROM (SELECT 1 AS _x) s"),
    ("reviewers", 'SELECT "1x" FROM (SELECT 1 AS "1x") s'),
    ("reviewers", "SELECT $$a$$ || $x$b$x$ AS c, $$it's$$ AS d, $$back\\slash$$ AS e"),
    (
        "reviewers",
        "SELECT 1.0 AS a, 1.50 AS b, 0.1 + 0.2 AS c, 1e-10 AS d, 1E10 AS e, 00012 AS f, 1.5e+3 AS g",
    ),
    (
        "reviewers",
        "SELECT 9223372036854775807 AS a, 9223372036854775808 AS b, -9223372036854775808 AS c",
    ),
    ("reviewers", "SELECT 3 AS a WHERE 1 = 1"),
    ("reviewers", "SELECT id FROM t WHERE TRUE ORDER BY id LIMIT 2"),
    ("reviewers", "SELECT id FROM t WHERE id = 1 AND FALSE"),
    ("reviewers", "SELECT id FROM t WHERE b = TRUE AND g <> '' ORDER BY id"),
    ("reviewers", "SELECT CAST(NULL AS text) AS n"),
    ("reviewers", "SELECT id FROM t WHERE x IS NULL IS FALSE ORDER BY id LIMIT 2"),
    ("reviewers", "SELECT id, g IS NOT DISTINCT FROM 'a' AS same FROM t ORDER BY id"),
    ("reviewers", "SELECT id, COALESCE(arr[3], -1) AS a3 FROM t ORDER BY id"),
    ("reviewers", "SELECT id, (arr)[2] AS a2, (tags)[1:1] AS t1 FROM t ORDER BY id"),
    ("reviewers", "SELECT id, (j -> 'a')[0] AS a0 FROM t WHERE id = 1"),
    (
        "reviewers",
        "SELECT id, upper(g)::text AS u, upper(g)::varchar(1) AS u1 FROM t ORDER BY id",
    ),
    ("reviewers", "SELECT id, substring(g, 1, 1) AS s FROM t ORDER BY id"),
    ("reviewers", 'SELECT id, g::text COLLATE "C" AS c FROM t ORDER BY id'),
    ("reviewers", 'SELECT id, g COLLATE "en_US" AS c FROM t WHERE id = 1'),
    ("reviewers", "SELECT id, lower(g) COLLATE \"C\" < 'b' AS c FROM t ORDER BY id"),
    (
        "reviewers",
        "SELECT id, char_length(g) + length(g::text) AS l, bit_length(g) AS bl FROM t ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT id, quote_literal(g) AS ql, quote_ident(g) AS qi, quote_nullable(g) AS qn FROM t WHERE id = 1",
    ),
    ("reviewers", "SELECT id, ascii(g) AS a, chr(65) AS c FROM t ORDER BY id"),
    (
        "reviewers",
        "SELECT id, to_hex(y) AS h, sha256(g::bytea) AS s FROM t WHERE id = 1",
    ),
    ("reviewers", "SELECT id, left(g, -1) AS a, right(g, -1) AS b FROM t ORDER BY id"),
    (
        "reviewers",
        "SELECT id, regexp_count('aaa', 'a') AS c, regexp_substr('abc', 'b') AS s FROM t WHERE id = 1",
    ),
    ("reviewers", "SELECT id, regexp_like(g, '^a') AS m FROM t ORDER BY id"),
    ("reviewers", "SELECT id, regexp_instr('abc', 'c') AS i FROM t WHERE id = 1"),
    ("reviewers", "SELECT id, string_agg(g, ', ') AS s FROM t GROUP BY id ORDER BY id"),
    (
        "reviewers",
        "SELECT id, array_to_json(arr) AS a, row_to_json(ROW(id, g)) AS r FROM t WHERE id = 1",
    ),
    (
        "reviewers",
        "SELECT id, json_object_agg(id, g) AS o FROM t GROUP BY id ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT id, to_json(x) AS a, jsonb_strip_nulls(j) AS b FROM t WHERE id = 1",
    ),
    ("reviewers", "SELECT g, jsonb_agg(j -> 'k') AS ks FROM t GROUP BY g ORDER BY g"),
    (
        "reviewers",
        "SELECT g, array_agg(arr) AS aa FROM t WHERE id < 3 GROUP BY g ORDER BY g",
    ),
    (
        "reviewers",
        "SELECT max(ts) - min(ts) AS span, avg(iv) AS ai, sum(iv) AS si FROM t",
    ),
    (
        "reviewers",
        "SELECT g, min(ts)::date AS first, max(ts)::date AS last FROM t GROUP BY g ORDER BY g",
    ),
    (
        "reviewers",
        "SELECT date_trunc('hour', ts) AS h, count(*) AS n FROM t GROUP BY date_trunc('hour', ts) ORDER BY h LIMIT 3",
    ),
    (
        "reviewers",
        "SELECT extract(year FROM d) * 100 + extract(month FROM d) AS ym FROM t ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT d, to_char(d, 'YYYY') || '-Q' || extract(quarter FROM d) AS q FROM t ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT id, d::timestamp + interval '1 hour' AS a, d + 1 AS b, d - 1 AS c FROM t ORDER BY id",
    ),
    ("reviewers", "SELECT id, (ts at time zone 'utc')::time AS t1 FROM t ORDER BY id"),
    (
        "reviewers",
        "SELECT id, cast(ts as date) AS c, date(ts) AS c2 FROM t ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT id, timestamp '2024-01-01' + y * interval '1 day' AS a FROM t ORDER BY id",
    ),
    (
        "reviewers",
        "SELECT id, interval '1 year 2 months 3 days' AS a, interval 'P1D' AS b FROM t WHERE id = 1",
    ),
    (
        "reviewers",
        "SELECT id, '2024-01-01 00:00:00+00'::timestamptz AS a FROM t WHERE id = 1",
    ),
    (
        "reviewers",
        "SELECT id, now()::timestamp(0) AS a, current_timestamp(0) AS b FROM t WHERE id = 1",
    ),
    ("reviewers", "SELECT id, localtime AS a, current_time AS b FROM t WHERE id = 1"),
    ("reviewers", "SELECT id, extract(julian FROM d) AS j FROM t WHERE id = 1"),
    (
        "reviewers",
        "SELECT id, date_part('isoyear', d) AS iy, date_part('week', d) AS w FROM t ORDER BY id",
    ),
    ("reviewers", "SELECT id, date_part('day', ts - ts) AS dd FROM t WHERE id = 1"),
    (
        "reviewers",
        "SELECT id, extract(day FROM ts - TIMESTAMPTZ '2024-01-01') AS dd FROM t ORDER BY id",
    ),
    # Review round 4: rewrites that changed results, now rendered as
    # written (see `parser.FaithfulPostgres`), plus LIMIT forms.
    (
        "as-written",
        "SELECT id, like(g, 'b%') AS l, like('abc', 'a%') AS m FROM t ORDER BY id",
    ),
    (
        "as-written",
        "SELECT id, strpos(g, 'a'), ceiling(x), char_length(g), character_length(g), pow(y, 2), mod(y, 3), log10(f), log10(x), substr(g, 1, 1), substr('abc', '2') FROM t ORDER BY id",
    ),
    (
        "as-written",
        "SELECT now(), now()::date, transaction_timestamp() = now() AS same FROM t WHERE id = 1",
    ),
    (
        "as-written",
        "SELECT g, variance(y), var_samp(y), stddev(y) FROM t GROUP BY g ORDER BY g",
    ),
    (
        "as-written",
        "SELECT id, to_char(d, 'YYYY %m %d') AS a, to_char(ts, '%H:%M HH24') AS b, to_char(x, '999D9%') AS c FROM t ORDER BY id",
    ),
    (
        "as-written",
        "SELECT id, date_bin('15 minutes', ts, '2001-01-01') AS a, date_bin('1 day', ts, TIMESTAMPTZ '2001-01-01') AS b FROM t ORDER BY id",
    ),
    (
        "as-written",
        "SELECT id, jsonb_contains(j, '{\"k\": 1}') AS a, jsonb_exists(j, 'k') AS b, json_object('{a,b}', '{1,2}') AS c, json_object('{a,1,b,2}') AS e FROM t ORDER BY id",
    ),
    (
        "as-written",
        "SELECT id, convert(g::bytea, 'UTF8', 'LATIN1') AS a, decode('aGk=', 'base64') AS b, encode('hi', 'base64') AS c, btrim(' x ') AS e, initcap(g) AS f FROM t ORDER BY id",
    ),
    (
        "as-written",
        "SELECT g, json_agg(y ORDER BY id) AS a, string_agg(DISTINCT upper(g), ', ' ORDER BY upper(g)) AS b, ceil(max(x)), floor(min(x)), chr(65 + max(y)) FROM t GROUP BY g ORDER BY g",
    ),
    (
        "as-written",
        "SELECT id, regexp_like(g, 'B', 'i') AS a, regexp_count(g, 'a') AS b, regexp_instr(g, 'b') AS c, regexp_substr(g, '[a-z]') AS e FROM t ORDER BY id",
    ),
    (
        "as-written",
        "SELECT id, date_add(ts, INTERVAL '1 day', 'Asia/Tokyo') AS a, date_add(ts, INTERVAL '1 month') AS b FROM t ORDER BY id",
    ),
    (
        "intervals",
        "SELECT INTERVAL '1 day 02:03:04' AS a, INTERVAL '3 days ago' AS b, INTERVAL '1 day 01:00', interval '-1 day +02:00' AS c, INTERVAL '2 hours', INTERVAL '5' DAY",
    ),
    (
        "intervals",
        "SELECT id, d + INTERVAL '1 day 06:00' AS a, ts - interval '1 day 2 hours ago' AS b FROM t ORDER BY id",
    ),
    (
        "json",
        "SELECT id, j -> 'n' ->> '' AS a, j -> '' AS b, j ->> 'a''b' AS c, j -> 'a' -> -1 AS e, j -> ('k') AS f, j -> 'Key' AS g FROM t ORDER BY id",
    ),
    (
        "rows",
        "SELECT id, (x, y) IS NOT NULL AS a, NOT (x, y) IS NULL AS b, ROW(x, y) IS NULL AS c, (x, y) NOTNULL AS e, y NOTNULL AS f, NOT y IS NOT NULL AS h FROM t ORDER BY id",
    ),
    (
        "rows",
        "SELECT id FROM t WHERE (x, y) IS NOT NULL AND (g, b) NOTNULL ORDER BY id",
    ),
    (
        "types",
        'SELECT id, x::"numeric"(10, 1) AS a, CAST(y AS "int8") AS b, 65::"char" AS c, g::"char" AS e, arr::"int8"[] AS f, \'011\'::"bit" AS h FROM t ORDER BY id',
    ),
    (
        "types",
        "SELECT bit '011', char 'abc', character 'abc', nchar 'abc', varchar 'abc', bit(3) '011', char(2) 'abc'",
    ),
    (
        "numbers",
        "SELECT 0x1F, 0o17, 0b101",
    ),
    (
        "numbers",
        "SELECT 1_000",
    ),
    (
        "numbers",
        "SELECT 1_000.5_0 AS a, .5_0 AS b, 1e1_0 AS c, 0x1F + 1 AS e, -0b11 AS f FROM t WHERE id = 0x1F",
    ),
    (
        "limit",
        "SELECT id FROM t ORDER BY id LIMIT 3.5",
    ),
    (
        "limit",
        "SELECT id FROM t ORDER BY id LIMIT 2 + 3",
    ),
    (
        "limit",
        "SELECT id FROM t ORDER BY id LIMIT (SELECT 3)",
    ),
    (
        "limit",
        "SELECT id FROM t ORDER BY id LIMIT NULL",
    ),
    (
        "limit",
        "(SELECT id FROM t ORDER BY id LIMIT 5)",
    ),
    (
        "limit",
        "SELECT id FROM t ORDER BY id LIMIT '4'",
    ),
    (
        "limit",
        "WITH a AS (SELECT id FROM t) (SELECT id FROM a ORDER BY id LIMIT 3)",
    ),
    (
        "limit",
        "SELECT id FROM t ORDER BY id LIMIT 0x3",
    ),
    # Review round 5.
    (
        "rows",
        "SELECT id, x IS NOT NULL IS TRUE AS a FROM t ORDER BY id",
    ),
    (
        "rows",
        "SELECT id FROM t WHERE x IS NOT NULL IS TRUE ORDER BY id",
    ),
    (
        "rows",
        "SELECT id, (x IS NOT NULL) IS TRUE AS a FROM t ORDER BY id",
    ),
    (
        "rows",
        "SELECT id, x IS NOT NULL IS FALSE AS a FROM t ORDER BY id",
    ),
    (
        "rows",
        "SELECT id, x IS NOT NULL IS NOT NULL AS a FROM t ORDER BY id",
    ),
    (
        "rows",
        "SELECT id, x IS NOT NULL IS NOT TRUE AS a FROM t ORDER BY id",
    ),
    (
        "rows",
        "SELECT id, x IS NULL IS NOT TRUE AS a FROM t ORDER BY id",
    ),
    (
        "rows",
        "SELECT id, b IS NOT TRUE IS TRUE AS a FROM t ORDER BY id",
    ),
    (
        "rows",
        "SELECT id, b IS NOT FALSE IS FALSE AS a FROM t ORDER BY id",
    ),
    (
        "rows",
        "SELECT id, b IS NOT TRUE AS a, b IS NOT FALSE AS c, b IS NOT UNKNOWN AS e FROM t ORDER BY id",
    ),
    (
        "rows",
        "SELECT id, x IS NOT NULL = true AS a FROM t ORDER BY id",
    ),
    (
        "rows",
        "SELECT id, NOT x IS NOT NULL IS TRUE AS a FROM t ORDER BY id",
    ),
    (
        "rows",
        "SELECT id, x NOTNULL IS TRUE AS a FROM t ORDER BY id",
    ),
    (
        "rows",
        "SELECT id, x ISNULL IS FALSE AS a FROM t ORDER BY id",
    ),
    (
        "rows",
        "SELECT id, x IS NOT NULL AND y IS NOT NULL AS a FROM t ORDER BY id",
    ),
    (
        "rows",
        "SELECT id, (x, y) IS NOT NULL IS TRUE AS a FROM t ORDER BY id",
    ),
    (
        "rows",
        "SELECT id, b IS NOT TRUE IS NOT TRUE AS a FROM t ORDER BY id",
    ),
    (
        "rows",
        "SELECT id, g IS NOT NULL IS NOT FALSE AS a FROM t ORDER BY id",
    ),
    (
        "rows",
        "SELECT id, j IS NOT NULL IS TRUE AS a FROM t ORDER BY id",
    ),
    (
        "rows",
        "SELECT count(*) FILTER (WHERE x IS NOT NULL IS TRUE) AS a FROM t",
    ),
    (
        "operators",
        "SELECT ~ -1, - ~1, ~ ~1, - -1",
    ),
    (
        "operators",
        "SELECT id, ~ -y AS a, - ~y AS b FROM t ORDER BY id",
    ),
    (
        "names",
        "SELECT qualify.id FROM t qualify ORDER BY 1 LIMIT 2",
    ),
    (
        "names",
        "SELECT c1 FROM t qualify (c1) ORDER BY 1 LIMIT 2",
    ),
    (
        "names",
        "SELECT x FROM (SELECT c1 AS x FROM t qualify (c1)) s ORDER BY 1 LIMIT 2",
    ),
    (
        "names",
        "SELECT id, (g).upper AS a, t.g AS b FROM t ORDER BY id",
    ),
    (
        "names",
        "SELECT pg_catalog.count(*) AS n, count(*) AS m FROM t",
    ),
    (
        "json",
        "SELECT id, j -> 'a'::text AS a, j -> y::text AS c FROM t ORDER BY id",
    ),
    # Review round 6.
    (
        "is-chains",
        "SELECT id, g NOT LIKE 'a%' IS TRUE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g NOT LIKE 'a%' IS NOT TRUE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g NOT LIKE 'a%' IS NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g NOT LIKE 'a%' IS NOT NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g NOT LIKE 'a%' IS FALSE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g NOT LIKE 'a%' IS NOT FALSE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g NOT LIKE 'a%' = true AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g NOT LIKE 'a%' <> false AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g NOT LIKE 'a%' AND true AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g NOT LIKE 'a%' OR false AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g NOT LIKE 'a%' IS DISTINCT FROM true AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g NOT LIKE 'a%' IS NOT DISTINCT FROM NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g NOT ILIKE 'A%' IS TRUE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g NOT ILIKE 'A%' IS NOT TRUE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g NOT ILIKE 'A%' IS NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g NOT ILIKE 'A%' IS NOT NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g NOT ILIKE 'A%' IS FALSE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g NOT ILIKE 'A%' IS NOT FALSE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g NOT ILIKE 'A%' = true AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g NOT ILIKE 'A%' <> false AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g NOT ILIKE 'A%' AND true AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g NOT ILIKE 'A%' OR false AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g NOT ILIKE 'A%' IS DISTINCT FROM true AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g NOT ILIKE 'A%' IS NOT DISTINCT FROM NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, y NOT BETWEEN 1 AND 3 IS TRUE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, y NOT BETWEEN 1 AND 3 IS NOT TRUE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, y NOT BETWEEN 1 AND 3 IS NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, y NOT BETWEEN 1 AND 3 IS NOT NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, y NOT BETWEEN 1 AND 3 IS FALSE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, y NOT BETWEEN 1 AND 3 IS NOT FALSE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, y NOT BETWEEN 1 AND 3 = true AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, y NOT BETWEEN 1 AND 3 <> false AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, y NOT BETWEEN 1 AND 3 AND true AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, y NOT BETWEEN 1 AND 3 OR false AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, y NOT BETWEEN 1 AND 3 IS DISTINCT FROM true AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, y NOT BETWEEN 1 AND 3 IS NOT DISTINCT FROM NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g NOT IN ('a', 'b') IS TRUE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g NOT IN ('a', 'b') IS NOT TRUE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g NOT IN ('a', 'b') IS NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g NOT IN ('a', 'b') IS NOT NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g NOT IN ('a', 'b') IS FALSE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g NOT IN ('a', 'b') IS NOT FALSE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g NOT IN ('a', 'b') = true AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g NOT IN ('a', 'b') <> false AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g NOT IN ('a', 'b') AND true AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g NOT IN ('a', 'b') OR false AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g NOT IN ('a', 'b') IS DISTINCT FROM true AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g NOT IN ('a', 'b') IS NOT DISTINCT FROM NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g NOT SIMILAR TO 'a%' IS TRUE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g NOT SIMILAR TO 'a%' IS NOT TRUE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g NOT SIMILAR TO 'a%' IS NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g NOT SIMILAR TO 'a%' IS NOT NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g NOT SIMILAR TO 'a%' IS FALSE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g NOT SIMILAR TO 'a%' IS NOT FALSE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g NOT SIMILAR TO 'a%' = true AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g NOT SIMILAR TO 'a%' <> false AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g NOT SIMILAR TO 'a%' AND true AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g NOT SIMILAR TO 'a%' OR false AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g NOT SIMILAR TO 'a%' IS DISTINCT FROM true AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g NOT SIMILAR TO 'a%' IS NOT DISTINCT FROM NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, x IS NOT DISTINCT FROM 1.37 AND true AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, x IS NOT DISTINCT FROM 1.37 OR false AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, x IS DISTINCT FROM 1.37 AND true AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, x IS DISTINCT FROM 1.37 OR false AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b IS NOT TRUE IS TRUE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b IS NOT TRUE IS NOT TRUE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b IS NOT TRUE IS NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b IS NOT TRUE IS NOT NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b IS NOT TRUE IS FALSE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b IS NOT TRUE IS NOT FALSE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b IS NOT TRUE = true AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b IS NOT TRUE <> false AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b IS NOT TRUE AND true AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b IS NOT TRUE OR false AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b IS NOT TRUE IS DISTINCT FROM true AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b IS NOT TRUE IS NOT DISTINCT FROM NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b IS NOT FALSE IS TRUE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b IS NOT FALSE IS NOT TRUE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b IS NOT FALSE IS NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b IS NOT FALSE IS NOT NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b IS NOT FALSE IS FALSE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b IS NOT FALSE IS NOT FALSE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b IS NOT FALSE = true AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b IS NOT FALSE <> false AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b IS NOT FALSE AND true AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b IS NOT FALSE OR false AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b IS NOT FALSE IS DISTINCT FROM true AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b IS NOT FALSE IS NOT DISTINCT FROM NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b IS NOT UNKNOWN IS TRUE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b IS NOT UNKNOWN IS NOT TRUE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b IS NOT UNKNOWN IS NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b IS NOT UNKNOWN IS NOT NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b IS NOT UNKNOWN IS FALSE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b IS NOT UNKNOWN IS NOT FALSE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b IS NOT UNKNOWN = true AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b IS NOT UNKNOWN <> false AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b IS NOT UNKNOWN AND true AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b IS NOT UNKNOWN OR false AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b IS NOT UNKNOWN IS DISTINCT FROM true AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b IS NOT UNKNOWN IS NOT DISTINCT FROM NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, x IS NOT NULL IS TRUE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, x IS NOT NULL IS NOT TRUE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, x IS NOT NULL IS NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, x IS NOT NULL IS NOT NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, x IS NOT NULL IS FALSE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, x IS NOT NULL IS NOT FALSE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, x IS NOT NULL = true AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, x IS NOT NULL <> false AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, x IS NOT NULL AND true AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, x IS NOT NULL OR false AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, x IS NOT NULL IS DISTINCT FROM true AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, x IS NOT NULL IS NOT DISTINCT FROM NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, x NOTNULL IS TRUE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, x NOTNULL IS NOT TRUE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, x NOTNULL IS NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, x NOTNULL IS NOT NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, x NOTNULL IS FALSE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, x NOTNULL IS NOT FALSE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, x NOTNULL = true AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, x NOTNULL <> false AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, x NOTNULL AND true AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, x NOTNULL OR false AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, x NOTNULL IS DISTINCT FROM true AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, x NOTNULL IS NOT DISTINCT FROM NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, NOT b IS TRUE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, NOT b IS NOT TRUE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, NOT b IS NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, NOT b IS NOT NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, NOT b IS FALSE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, NOT b IS NOT FALSE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, NOT b = true AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, NOT b <> false AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, NOT b AND true AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, NOT b OR false AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, NOT b IS DISTINCT FROM true AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, NOT b IS NOT DISTINCT FROM NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b IS TRUE IS TRUE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b IS TRUE IS NOT TRUE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b IS TRUE IS NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b IS TRUE IS NOT NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b IS TRUE IS FALSE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b IS TRUE IS NOT FALSE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b IS TRUE = true AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b IS TRUE <> false AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b IS TRUE AND true AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b IS TRUE OR false AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b IS TRUE IS DISTINCT FROM true AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b IS TRUE IS NOT DISTINCT FROM NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, y > 2 IS TRUE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, y > 2 IS NOT TRUE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, y > 2 IS NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, y > 2 IS NOT NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, y > 2 IS FALSE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, y > 2 IS NOT FALSE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, y > 2 AND true AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, y > 2 OR false AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, y > 2 IS DISTINCT FROM true AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, y > 2 IS NOT DISTINCT FROM NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, y = 1 IS TRUE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, y = 1 IS NOT TRUE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, y = 1 IS NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, y = 1 IS NOT NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, y = 1 IS FALSE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, y = 1 IS NOT FALSE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, y = 1 AND true AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, y = 1 OR false AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, y = 1 IS DISTINCT FROM true AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, y = 1 IS NOT DISTINCT FROM NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g ~ 'a' IS TRUE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g ~ 'a' IS NOT TRUE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g ~ 'a' IS NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g ~ 'a' IS NOT NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g ~ 'a' IS FALSE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g ~ 'a' IS NOT FALSE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g ~ 'a' = true AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g ~ 'a' <> false AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g ~ 'a' AND true AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g ~ 'a' OR false AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g ~ 'a' IS DISTINCT FROM true AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g ~ 'a' IS NOT DISTINCT FROM NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g !~ 'a' IS TRUE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g !~ 'a' IS NOT TRUE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g !~ 'a' IS NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g !~ 'a' IS NOT NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g !~ 'a' IS FALSE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g !~ 'a' IS NOT FALSE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g !~ 'a' = true AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g !~ 'a' <> false AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g !~ 'a' AND true AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g !~ 'a' OR false AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g !~ 'a' IS DISTINCT FROM true AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g !~ 'a' IS NOT DISTINCT FROM NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g !~~ 'a%' IS TRUE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g !~~ 'a%' IS NOT TRUE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g !~~ 'a%' IS NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g !~~ 'a%' IS NOT NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g !~~ 'a%' IS FALSE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g !~~ 'a%' IS NOT FALSE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g !~~ 'a%' = true AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g !~~ 'a%' <> false AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g !~~ 'a%' AND true AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g !~~ 'a%' OR false AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g !~~ 'a%' IS DISTINCT FROM true AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, g !~~ 'a%' IS NOT DISTINCT FROM NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b = true IS NOT TRUE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, y = 3 IS NOT TRUE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b <> true IS NOT TRUE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, y <> 3 IS NOT TRUE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b < true IS NOT TRUE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, y < 3 IS NOT TRUE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b >= true IS NOT TRUE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, y >= 3 IS NOT TRUE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b AND true IS NOT TRUE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b AND b IS NOT TRUE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b OR true IS NOT TRUE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b OR b IS NOT TRUE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id FROM t WHERE NOT b IS NOT TRUE ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id FROM t WHERE NOT NOT b IS NOT TRUE ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b = true IS NOT FALSE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, y = 3 IS NOT FALSE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b <> true IS NOT FALSE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, y <> 3 IS NOT FALSE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b < true IS NOT FALSE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, y < 3 IS NOT FALSE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b >= true IS NOT FALSE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, y >= 3 IS NOT FALSE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b AND true IS NOT FALSE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b AND b IS NOT FALSE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b OR true IS NOT FALSE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b OR b IS NOT FALSE AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id FROM t WHERE NOT b IS NOT FALSE ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id FROM t WHERE NOT NOT b IS NOT FALSE ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b = true IS NOT UNKNOWN AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, y = 3 IS NOT UNKNOWN AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b <> true IS NOT UNKNOWN AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, y <> 3 IS NOT UNKNOWN AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b < true IS NOT UNKNOWN AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, y < 3 IS NOT UNKNOWN AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b >= true IS NOT UNKNOWN AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, y >= 3 IS NOT UNKNOWN AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b AND true IS NOT UNKNOWN AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b AND b IS NOT UNKNOWN AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b OR true IS NOT UNKNOWN AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b OR b IS NOT UNKNOWN AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id FROM t WHERE NOT b IS NOT UNKNOWN ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id FROM t WHERE NOT NOT b IS NOT UNKNOWN ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b = true IS NOT NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, y = 3 IS NOT NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b <> true IS NOT NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, y <> 3 IS NOT NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b < true IS NOT NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, y < 3 IS NOT NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b >= true IS NOT NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, y >= 3 IS NOT NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b AND true IS NOT NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b AND b IS NOT NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b OR true IS NOT NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b OR b IS NOT NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id FROM t WHERE NOT b IS NOT NULL ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id FROM t WHERE NOT NOT b IS NOT NULL ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b = true IS NOT DISTINCT FROM NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, y = 3 IS NOT DISTINCT FROM NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b <> true IS NOT DISTINCT FROM NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, y <> 3 IS NOT DISTINCT FROM NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b < true IS NOT DISTINCT FROM NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, y < 3 IS NOT DISTINCT FROM NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b >= true IS NOT DISTINCT FROM NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, y >= 3 IS NOT DISTINCT FROM NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b AND true IS NOT DISTINCT FROM NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b AND b IS NOT DISTINCT FROM NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b OR true IS NOT DISTINCT FROM NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b OR b IS NOT DISTINCT FROM NULL AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id FROM t WHERE NOT b IS NOT DISTINCT FROM NULL ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id FROM t WHERE NOT NOT b IS NOT DISTINCT FROM NULL ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b = true IS DISTINCT FROM true AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, y = 3 IS DISTINCT FROM true AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b <> true IS DISTINCT FROM true AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, y <> 3 IS DISTINCT FROM true AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b < true IS DISTINCT FROM true AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, y < 3 IS DISTINCT FROM true AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b >= true IS DISTINCT FROM true AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, y >= 3 IS DISTINCT FROM true AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b AND true IS DISTINCT FROM true AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b AND b IS DISTINCT FROM true AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b OR true IS DISTINCT FROM true AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id, b OR b IS DISTINCT FROM true AS a FROM t ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id FROM t WHERE NOT b IS DISTINCT FROM true ORDER BY id",
    ),
    (
        "is-chains",
        "SELECT id FROM t WHERE NOT NOT b IS DISTINCT FROM true ORDER BY id",
    ),
    (
        "attribute-columns",
        "SELECT s.lo_bound FROM (SELECT min(y) AS lo_bound FROM t) s",
    ),
    (
        "attribute-columns",
        "SELECT s.array_agg FROM (SELECT g, array_agg(y ORDER BY id) FROM t GROUP BY g) s ORDER BY 1",
    ),
    (
        "attribute-columns",
        "WITH c AS (SELECT count(*) AS currval FROM t) SELECT c.currval FROM c",
    ),
    (
        "attribute-columns",
        "SELECT s.copy, s.unnest FROM (SELECT 1 AS copy, 2 AS unnest) s",
    ),
    (
        "attribute-columns",
        "SELECT x.pg_sleep FROM (SELECT 0.1::float8 AS v) AS x(pg_sleep)",
    ),
    (
        "attribute-columns",
        "SELECT s.pg_rank FROM (SELECT rank() OVER (ORDER BY y, id) AS pg_rank FROM t) s ORDER BY 1 LIMIT 1",
    ),
    (
        "attribute-columns",
        "SELECT '0/0'::pg_catalog.pg_lsn AS v",
    ),
    (
        "json",
        "SELECT id, j #> '{n,m}'::text[] AS a, j #>> '{n,m}'::text[] AS b, j ? 'k'::text AS c FROM t ORDER BY id",
    ),
    (
        "json",
        "SELECT id FROM t WHERE j #>> '{n,m}'::text[] = '1' ORDER BY id",
    ),
    (
        "operators",
        "SELECT 2 ^ 3, (2 ^ 3) ^ 2, 2 ^ 3 ^ 2",
    ),
    (
        "operators",
        "SELECT id, g !~ 'a' AS a, g !~~ 'a%' AS b, g !~* 'A' AS c FROM t ORDER BY id",
    ),
    # Review round 7.
    (
        "json",
        "SELECT json_object(ARRAY[g], ARRAY[format('%s', id)]) AS o FROM t WHERE id = 1",
    ),
    (
        "json",
        "SELECT json_object(ARRAY['on', 'x']) AS a, json_object(ARRAY['a', 'b'], ARRAY['on', 'x']) AS b",
    ),
    (
        "json",
        "SELECT id, json_object(tags[1:2]) AS a FROM t WHERE id < 4 ORDER BY id",
    ),
    (
        "json",
        "SELECT json_object(ARRAY[s.key], ARRAY[s.value]) AS o FROM (SELECT 'k' AS key, '1' AS value) s",
    ),
    (
        "intervals",
        "SELECT INTERVAL '25 hours' DAY, INTERVAL '13 months' YEAR AS y, INTERVAL '1 day' DAY AS d",
    ),
    (
        "intervals",
        "SELECT INTERVAL '1 day 02:03' DAY TO SECOND AS a, INTERVAL '5' DAY AS b, INTERVAL '1:30' HOUR TO MINUTE AS c",
    ),
    (
        "limit",
        "SELECT id FROM t ORDER BY id LIMIT '9223372036854775807'",
    ),
    (
        "limit",
        "SELECT id FROM t ORDER BY id LIMIT ' +3 '",
    ),
    (
        "operators",
        "SELECT id, @ -5 AS a, @ (y - 5) AS b, @ x AS c FROM t ORDER BY id",
    ),
    (
        "operators",
        "SELECT @-@ '((0,0),(1,1))'::lseg AS a",
    ),
    (
        "names",
        "SELECT id qualify FROM t ORDER BY id",
    ),
    (
        "names",
        "SELECT qualify, count(*) AS n FROM (SELECT y AS qualify FROM t) s GROUP BY qualify ORDER BY qualify",
    ),
    (
        "as-written",
        "SELECT overlaps(DATE '2001-01-01', DATE '2001-01-02', d, d + 1) AS o FROM t ORDER BY id",
    ),
    (
        "attribute-columns",
        'SELECT s."Pg_Sleep" FROM (SELECT 1 AS "Pg_Sleep") s',
    ),
    (
        "intervals",
        "SELECT INTERVAL '25 hours' \"DAY\", INTERVAL '3 months' \"YEAR\", INTERVAL '1' DAY \"TO\"",
    ),
    (
        "intervals",
        "SELECT INTERVAL '1' DAY TO SECOND(3) AS a, INTERVAL '1.234' SECOND(2) AS b, INTERVAL '1.234' SECOND (2) AS c, INTERVAL '61.5678' MINUTE TO SECOND(1) AS e, INTERVAL '1.5' HOUR TO SECOND(0) AS f",
    ),
    (
        "json",
        "SELECT json_object('a' VALUE NULL ABSENT ON NULL) AS a, json_object('a' VALUE 1 RETURNING jsonb) AS b, json_object('k': '{\"x\": 1}' FORMAT JSON) AS c, json_object('a' VALUE id) AS e FROM t WHERE id < 3 ORDER BY id",
    ),
    (
        "intervals",
        "SELECT INTERVAL '1' \"day\", INTERVAL '2' \"Second\", INTERVAL '1.5' SECOND(3) AS v, INTERVAL '1 day 2 hours' \"x\"",
    ),
    (
        "intervals",
        "SELECT id, INTERVAL(3) '1.23456' AS a, INTERVAL (0) '2.5 seconds' AS b, iv + INTERVAL(1) '0.25' AS c FROM t ORDER BY id",
    ),
    (
        "limit",
        "SELECT id FROM t ORDER BY id LIMIT ('5000000000')",
    ),
    (
        "limit",
        "SELECT id FROM t ORDER BY id LIMIT ((' +3 '))",
    ),
    (
        "limit",
        "SELECT id FROM t ORDER BY id LIMIT (SELECT 2.5::numeric AS n)",
    ),
    (
        "arrays",
        'SELECT id, s."array"[1] AS a, "array"[2] AS b, s.array[1:2] AS c, list[1] AS e, s.list[2] AS f FROM (SELECT id, arr AS "array", tags AS list FROM t) s ORDER BY id',
    ),
    (
        "arrays",
        "SELECT (ARRAY(SELECT y FROM t ORDER BY id))[2] AS a, (ARRAY[[1, 2], [3, 4]])[2][1] AS b, json_object((ARRAY['a', 'b', 'c', 'd'])[1:2]) AS c",
    ),
    (
        "json",
        "SELECT json_object(key VALUE id) AS a, json_object(\"KEY\" VALUE id) AS b, json_object(s.key: s.id) AS c FROM (SELECT 'k' AS key, 'K' AS \"KEY\", id FROM t WHERE id < 3) s ORDER BY id",
    ),
    (
        "intervals",
        "SELECT INTERVAL '1' WEEK, INTERVAL '2' DAYS, INTERVAL '3' q, INTERVAL '4' MON, INTERVAL '5' hr, INTERVAL '1 week' AS w",
    ),
    (
        "names",
        'SELECT "user", "current_user" FROM (SELECT g AS "user", id AS "current_user" FROM t WHERE id < 3) s ORDER BY 2',
    ),
    (
        "operators",
        "SELECT '10' ^@ '1' AS a, '4' ^@ '2' AS b, 'x' || 'abc' ^@ 'a' AS c",
    ),
    (
        "operators",
        "SELECT id, g ^@ 'a' AS a, NOT g ^@ 'A' AS b FROM t ORDER BY id",
    ),
    (
        "operators",
        "SELECT !! to_tsquery('simple', 'a') AS a, !!'b'::tsquery && 'c'::tsquery AS b",
    ),
    (
        "attribute-columns",
        "SELECT (s).copy AS v FROM (SELECT 1 AS copy) s",
    ),
    (
        "attribute-columns",
        "SELECT (s).pg_sleep AS a, s.pg_column_size AS b FROM (SELECT 1 AS pg_sleep, (SELECT 2 AS pg_column_size)) s",
    ),
    (
        "attribute-columns",
        "SELECT p.pg_sleep AS a, (v).column2 AS b FROM (SELECT 9 AS pg_sleep) p, (VALUES (1, 'a'), (2, 'b')) v ORDER BY 2",
    ),
    (
        "cte-names",
        "WITH u AS (SELECT id, amount FROM u WHERE id < 4) SELECT id, amount FROM u ORDER BY id",
    ),
    (
        "cte-names",
        'WITH x AS (SELECT id FROM t WHERE id < 3), "X" AS (SELECT 5 AS id) SELECT id FROM x UNION ALL SELECT id FROM "X" ORDER BY id',
    ),
    (
        "intervals",
        "SELECT INTERVAL E'1' week, INTERVAL $$2$$ days, INTERVAL $t$3$t$ q, INTERVAL $$25 hours$$ DAY AS a, INTERVAL E'25 hours' DAY AS b, INTERVAL $$1$$ \"day\", INTERVAL $$1-2$$ YEAR TO MONTH AS c, INTERVAL E'1 week' AS w",
    ),
    (
        "intervals",
        "SELECT id, d + INTERVAL $$1$$ week FROM t WHERE id < 4 ORDER BY id",
    ),
    (
        "intervals",
        "SELECT INTERVAL(2) $$1.234$$ AS a, INTERVAL(2) E'1.234' AS b, INTERVAL $$1.5$$ SECOND(3) AS c, INTERVAL $$1$$ * 2 AS e",
    ),
    (
        "intervals",
        "SELECT id, INTERVAL '1 day' + 2 * iv AS a, INTERVAL '1 day' + 2 * INTERVAL '1 hour' AS b, INTERVAL '1 day' + '1 hour' AS c FROM t ORDER BY id",
    ),
    (
        "intervals",
        "SELECT INTERVAL '90 seconds' m\u0131nute, INTERVAL '1.789' \u017fecond",
    ),
    (
        "limit",
        "SELECT id FROM t ORDER BY id LIMIT $$5000000000$$",
    ),
    (
        "limit",
        "SELECT id FROM t ORDER BY id LIMIT E' 5000000000 '",
    ),
    (
        "typed-literals",
        "SELECT DATE $$2024-01-01$$ AS a, TIMESTAMP E'2024-01-01 10:00' AS b, bit $$011$$ AS c, char E'abc' AS e, d - DATE $t$2024-01-01$t$ AS f FROM t ORDER BY id",
    ),
    (
        "intervals",
        "SELECT id, interval + 1 AS v FROM (SELECT id, y AS interval FROM t) s ORDER BY id",
    ),
    (
        "intervals",
        "SELECT id, interval - 1 AS v FROM (SELECT id, y AS interval FROM t) s ORDER BY id",
    ),
    (
        "intervals",
        "SELECT id, interval + '1' AS v FROM (SELECT id, y AS interval FROM t) s ORDER BY id",
    ),
    (
        "intervals",
        "SELECT id, interval - y AS v FROM (SELECT id, id AS interval, y FROM t) s ORDER BY id",
    ),
    (
        "intervals",
        "SELECT id, interval[1] AS v FROM (SELECT id, arr AS interval FROM t) s ORDER BY id",
    ),
    (
        "intervals",
        "SELECT id, interval ~ '^a' AS v FROM (SELECT id, g AS interval FROM t) s ORDER BY id",
    ),
    (
        "intervals",
        'SELECT id, interval COLLATE "C" AS v FROM (SELECT id, g AS interval FROM t) s ORDER BY v, id',
    ),
    (
        "intervals",
        "SELECT id, interval % 3 AS v FROM (SELECT id, y AS interval FROM t) s ORDER BY id",
    ),
    (
        "intervals",
        "SELECT id FROM (SELECT id, y AS interval FROM t) s WHERE interval + 1 > 2 ORDER BY id",
    ),
    (
        "intervals",
        "SELECT id, interval * 2 AS v FROM (SELECT id, y AS interval FROM t) s ORDER BY id",
    ),
    (
        "intervals",
        "SELECT id, interval / 2 AS v FROM (SELECT id, y AS interval FROM t) s ORDER BY id",
    ),
    (
        "intervals",
        "SELECT id, interval ^ 2 AS v FROM (SELECT id, y AS interval FROM t) s ORDER BY id",
    ),
    (
        "intervals",
        "SELECT id, interval[:] AS v FROM (SELECT id, arr AS interval FROM t) s ORDER BY id",
    ),
    (
        "intervals",
        "SELECT id, interval[:1] AS v FROM (SELECT id, arr AS interval FROM t) s ORDER BY id",
    ),
    (
        "intervals",
        "SELECT id, INTERVAL[:1] AS v FROM (SELECT id, arr AS interval FROM t) s ORDER BY id",
    ),
    (
        "intervals",
        "SELECT id, interval [:1] AS v FROM (SELECT id, arr AS interval FROM t) s ORDER BY id",
    ),
    (
        "intervals",
        "SELECT id, interval[ :1] AS v FROM (SELECT id, arr AS interval FROM t) s ORDER BY id",
    ),
    (
        "intervals",
        "SELECT id, interval[2:] AS v FROM (SELECT id, arr AS interval FROM t) s ORDER BY id",
    ),
    (
        "patterns",
        "SELECT id, g ILIKE 'A%' ESCAPE E'#' AS v FROM t ORDER BY id",
    ),
    (
        "typed-literals",
        "SELECT char(2) E'abcd' AS a",
    ),
    (
        "typed-literals",
        "SELECT time(1) E'10:00:00.66' AS a",
    ),
    # Review round 17: interval type modifiers in a cast (sqlglot rendered
    # `interval(1)` as `INTERVAL 1`, and read `second(2)` as an alias list).
    (
        "intervals",
        "SELECT id, '12.345'::interval(1) AS a, CAST('1.2345' AS interval(3)) AS b, iv::interval(0) AS c FROM t ORDER BY id",
    ),
    (
        "intervals",
        "SELECT '1 day 12:00:00.123'::interval day to second(2) AS a, '1.234'::interval second(2) AS b, CAST('1.234' AS interval second(1)) AS c, '61.5'::interval minute to second(0) AS d",
    ),
    (
        "intervals",
        "SELECT '{1.234}'::interval(1)[] AS a, ARRAY['1.25']::interval(1)[] AS b, '{1.234}'::interval second(1)[] AS c, '{1.234}'::interval day to second(2)[] AS d",
    ),
    (
        "intervals",
        "SELECT '1.25'::INTERVAL ( 1 ) + '1' AS a, '1.25'::interval(1)::text AS b, '7.5'::interval(0) AS c",
    ),
    # Review round 18: a word after an interval type that is not a field is
    # an alias (sqlglot ran `days` as `INTERVAL DAY`, `h` as `HOUR`).
    (
        "intervals",
        "SELECT id, '90'::interval days, '1'::interval h, '1.234'::interval(1) secs, iv::interval week FROM t ORDER BY id",
    ),
    # Review round 19: `ARRAY` after a type (sqlglot dropped it at the end of
    # the input, made it an alias before a comma, refused it before an
    # operator), a bound after a type (rendered as a subscript of the cast),
    # `bit varying` (ran as `bit(1)`), a word after the quoted `"interval"`
    # (dropped).
    (
        "arrays",
        "SELECT id, tags::text array, arr::int array[4] AS b, '{1}'::interval day array AS c FROM t ORDER BY id",
    ),
    (
        "arrays",
        "SELECT id FROM t WHERE tags::text array && '{y}' ORDER BY id, tags::varchar array",
    ),
    (
        "arrays",
        "SELECT cardinality(arr::bigint array) AS a, '{1.5}'::double precision array AS b, '{1}'::int[3] AS c, '{1}'::int[][2] AS d FROM t WHERE id = 1",
    ),
    (
        "arrays",
        "SELECT id, g::bit varying AS a, '{101}'::bit varying(2) array AS b, '10101'::bit varying FROM (SELECT id, '1' AS g FROM t) s WHERE id < 3 ORDER BY id",
    ),
    (
        "intervals",
        "SELECT '90'::\"interval\" days, '90'::pg_catalog.interval h, '{9}'::\"interval\" array[2] AS c",
    ),
    # Review round 20: `OPERATOR(schema.op)` keeps its name as written (a
    # quoted qualifier came back unquoted: another operator; see
    # `SETUP_SQL`), the prefix form runs, operators sqlglot cannot read bare
    # run in this form, `x operator` keeps its alias (sqlglot 30.7 dropped
    # it) and `!~ x` is the prefix operator `!~` (sqlglot: `! ~x`).
    (
        "operators",
        "SELECT id, g OPERATOR(\"McpOps\".=) 'a' AS q, g OPERATOR(mcpops.=) 'a' AS f, g OPERATOR(McpOps.=) 'a' AS u FROM t WHERE id <= 6 ORDER BY id",
    ),
    (
        "operators",
        "SELECT id FROM t WHERE g OPERATOR(\"mcp ops\".=) 'b' ORDER BY id",
    ),
    (
        "operators",
        'SELECT id, y OPERATOR("mcp""ops".+) 1 AS v, y OPERATOR(pg_catalog.+) 1 AS w FROM t WHERE id <= 3 ORDER BY id',
    ),
    (
        "operators",
        'SELECT id, OPERATOR("McpOps".-) (y - 3) AS a, OPERATOR(mcpops.-) (y - 3) AS b, OPERATOR(pg_catalog.-) y + 1 AS c FROM t WHERE id <= 4 ORDER BY id',
    ),
    (
        "operators",
        "SELECT id FROM t WHERE g OPERATOR( \"McpOps\" . = ) 'a' AND g OPERATOR(pg_catalog./* c */=) 'a' ORDER BY id",
    ),
    (
        "operators",
        "SELECT id, g OPERATOR(pg_catalog.~<~) 'b' AS lt, g OPERATOR(pg_catalog.~>=~) 'b' AS ge FROM t WHERE id <= 6 ORDER BY id",
    ),
    (
        "operators",
        "SELECT OPERATOR(pg_catalog.|/) y AS r, OPERATOR(pg_catalog.||/) y, OPERATOR(pg_catalog.@) (y - 3) AS a FROM t WHERE id <= 5 ORDER BY id",
    ),
    (
        "operators",
        "SELECT id, y OPERATOR(pg_catalog.+) 1 OPERATOR(pg_catalog.*) 2 AS v, 2 OPERATOR(pg_catalog.*) y + 1 AS w, 1 OPERATOR(pg_catalog.+) y || 'x' AS s FROM t WHERE id <= 4 ORDER BY id",
    ),
    (
        "operators",
        "SELECT id, y operator FROM t WHERE id <= 3 ORDER BY id",
    ),
    (
        "operators",
        "SELECT id FROM t WHERE y OPERATOR(pg_catalog.=) ANY (ARRAY[1, 2]) ORDER BY id",
    ),
    (
        "operators",
        "SELECT id, !~ g AS v, g OPERATOR(pg_catalog.~) !~ 'b' AS w FROM t WHERE id <= 4 ORDER BY id",
    ),
    (
        "operators",
        "SELECT g OPERATOR(pg_catalog.||) id::text AS s FROM t WHERE id OPERATOR(pg_catalog.<) 3 ORDER BY id OPERATOR(pg_catalog.-) 0",
    ),
    (
        "operators",
        "SELECT g, count(*) FILTER (WHERE y OPERATOR(pg_catalog.>) 2) AS n FROM t GROUP BY g HAVING sum(y) OPERATOR(pg_catalog.>) 0 ORDER BY g",
    ),
    # `nchar varying` is `varchar` (refused in round 19; Opus final 11).
    (
        "types",
        "SELECT id, g::nchar varying AS a, 'abc'::nchar varying(2) AS b, CAST(g AS NCHAR VARYING(1)) AS c, '{abc}'::nchar varying(1)[] AS e, nchar varying 'xy' FROM t WHERE id <= 3 ORDER BY id",
    ),
    (
        "types",
        "SELECT id, '1'::\"int4\" AS a, '{1}'::\"int4\"[2] AS b, '1.234'::\"numeric\"(10, 2) AS c, '{9}'::\"interval\"[] AS e FROM t WHERE id = 1",
    ),
]

REFUSED: list[tuple[str, str]] = [
    ("disallowed_construct", "SELECT generate_series(1, 3) AS s"),
    ("disallowed_construct", "SELECT s.i FROM generate_series(1, 3) AS s(i)"),
    (
        "disallowed_construct",
        "SELECT t.id, s.i FROM t CROSS JOIN LATERAL generate_series(1, t.y) AS s(i) WHERE t.id < 4 ORDER BY 1, 2",
    ),
    (
        "disallowed_construct",
        "SELECT t.id, e.v FROM t, unnest(t.tags) AS e(v) WHERE t.id < 3 ORDER BY 1, 2",
    ),
    (
        "disallowed_construct",
        "SELECT id, x FROM t ORDER BY x DESC FETCH FIRST 3 ROWS ONLY",
    ),
    ("disallowed_construct", "SELECT id FROM t ORDER BY id OFFSET 5"),
    ("disallowed_construct", "SELECT id, g FROM t WHERE g = 'a' FOR UPDATE"),
    ("select_star", "SELECT * FROM t"),
    ("select_star", "SELECT t.* FROM t"),
    (
        "disallowed_construct",
        "SELECT id, (SELECT string_agg(v, ',') FROM unnest(tags) AS v) AS s FROM t ORDER BY id",
    ),
    (
        "roundtrip_mismatch",
        "SELECT id, lag(y, 1) IGNORE NULLS OVER (ORDER BY id) AS l FROM t ORDER BY id",
    ),
    ("disallowed_function", "SELECT id, pg_typeof(x) AS ty FROM t WHERE id = 1"),
    ("disallowed_function", "SELECT id, current_user AS cu FROM t WHERE id = 1"),
    ("disallowed_function", "SELECT id, version() AS v FROM t WHERE id = 1"),
    (
        "disallowed_construct",
        "SELECT id, jsonb_array_elements_text(j -> 'a') AS e FROM t WHERE id = 1",
    ),
    (
        "disallowed_construct",
        "SELECT t.id, e.value FROM t, jsonb_array_elements(t.j -> 'a') AS e WHERE t.id < 3 ORDER BY 1, 2",
    ),
    (
        "disallowed_construct",
        "SELECT t.id, k.key FROM t, jsonb_object_keys(t.j) AS k(key) WHERE t.id = 1 ORDER BY 2",
    ),
    (
        "disallowed_construct",
        "SELECT t.id, e.key, e.value FROM t, jsonb_each(t.j) AS e WHERE t.id = 1 ORDER BY 2",
    ),
    (
        "disallowed_construct",
        "SELECT id, regexp_matches('a1b2', '[0-9]', 'g') AS m FROM t WHERE id = 1",
    ),
    (
        "disallowed_construct",
        "SELECT x FROM (SELECT unnest(ARRAY[3, 1, 2]) AS x) s ORDER BY x",
    ),
    (
        "disallowed_construct",
        "SELECT x FROM unnest(ARRAY[3, 1, 2]) WITH ORDINALITY AS s(x, n) ORDER BY n",
    ),
    (
        "disallowed_construct",
        "SELECT a, b FROM ROWS FROM (generate_series(1, 2), generate_series(3, 5)) AS r(a, b) ORDER BY 2",
    ),
    ("select_star", "SELECT * FROM (SELECT id FROM t) s"),
    (
        "disallowed_construct",
        "WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM r WHERE n < 3) SELECT n FROM r",
    ),
    (
        "parse_error",
        "SELECT id, nth_value(y, 2) FROM LAST OVER (ORDER BY id) AS n FROM t ORDER BY id",
    ),
    (
        "roundtrip_mismatch",
        "SELECT id, lead(y) RESPECT NULLS OVER (ORDER BY id) AS l FROM t ORDER BY id",
    ),
    (
        "roundtrip_mismatch",
        "SELECT id, first_value(y) IGNORE NULLS OVER (ORDER BY id) AS l FROM t ORDER BY id",
    ),
    (
        "parse_error",
        "SELECT id FROM t QUALIFY row_number() OVER (PARTITION BY g ORDER BY id) = 1",
    ),
    (
        "parse_error",
        "SELECT id FROM t WHERE id IN (SELECT id FROM t QUALIFY row_number() OVER (ORDER BY id DESC) <= 2 LIMIT 5) ORDER BY id",
    ),
    ("parse_error", "SELECT id, y DIV 2 AS i FROM t ORDER BY id"),
    ("parse_error", "SELECT id FROM t ORDER BY id USING >"),
    ("parse_error", "SELECT DISTINCT ON (g) g, id FROM t ORDER BY g, id USING <"),
    ("disallowed_construct", "SELECT id, x FROM t LIMIT 3 OFFSET 0"),
    (
        "disallowed_construct",
        "SELECT id, generate_subscripts(arr, 1) AS s FROM t WHERE id = 1",
    ),
    (
        "disallowed_function",
        "SELECT ('server_version'::text).current_setting AS v",
    ),
    (
        "disallowed_function",
        "SELECT ('search_path'::text).current_setting AS v",
    ),
    (
        "disallowed_function",
        "SELECT (true).current_schemas AS v",
    ),
    (
        "disallowed_function",
        "SELECT (0.1::float8).pg_sleep AS v",
    ),
    (
        "disallowed_function",
        "SELECT (10::oid).pg_get_userbyid AS v",
    ),
    (
        "disallowed_function",
        "SELECT ('t'::regclass).pg_relation_size AS v",
    ),
    (
        "disallowed_function",
        "SELECT (424242::bigint).pg_try_advisory_lock AS v",
    ),
    (
        "disallowed_function",
        "SELECT t.pg_column_size AS v FROM t WHERE id = 1",
    ),
    (
        "disallowed_function",
        "SELECT (t.g).current_setting AS v FROM t WHERE id = 1",
    ),
    (
        "select_star",
        "SELECT t.to_jsonb AS v FROM t WHERE id = 1",
    ),
    (
        "select_star",
        "SELECT t.row_to_json FROM t LIMIT 1",
    ),
    (
        "disallowed_construct",
        "SELECT (ARRAY[1,2]).unnest AS v",
    ),
    (
        "disallowed_construct",
        "SELECT pg_catalog.generate_series(1, 3) AS v",
    ),
    (
        "disallowed_construct",
        "SELECT CASE WHEN true THEN pg_catalog.unnest(arr) END AS c FROM t",
    ),
    (
        "disallowed_function",
        "SELECT (SELECT copy(x)) AS c FROM t",
    ),
    (
        "disallowed_function",
        "SELECT c FROM t WHERE c = ANY(copy(x))",
    ),
    (
        "unsafe_literal",
        "SELECT 2 %-3 AS v",
    ),
    (
        "parse_error",
        "SELECT json_object(KEY 'a' VALUE 1) AS a",
    ),
    (
        "unsafe_literal",
        "SELECT id, y=~1 AS a FROM t ORDER BY id",
    ),
    (
        "unsafe_literal",
        "SELECT id, -~y AS a FROM t ORDER BY id",
    ),
    (
        "select_star",
        "SELECT t.concat AS v FROM t LIMIT 1",
    ),
    (
        "select_star",
        "SELECT t.quote_literal AS v FROM t LIMIT 1",
    ),
    (
        "select_star",
        "SELECT t.record_out AS v FROM t LIMIT 1",
    ),
    (
        "select_star",
        "SELECT t.record_send AS v FROM t LIMIT 1",
    ),
    (
        "disallowed_function",
        "SELECT (1).pg_typeof AS v",
    ),
    (
        "disallowed_function",
        "SELECT u.pg_typeof AS v FROM t AS u LIMIT 1",
    ),
    (
        "disallowed_function",
        "SELECT s.pg_typeof AS v FROM (SELECT 1 AS a) s",
    ),
    (
        "unsafe_literal",
        "SELECT id FROM t WHERE y ==1",
    ),
    (
        "unsafe_literal",
        "SELECT id FROM t WHERE y <=> 1",
    ),
    (
        "disallowed_function",
        "SELECT (x).current_setting AS v FROM (SELECT 'server_version'::text AS x, 1 AS current_setting) x",
    ),
    (
        "disallowed_function",
        "SELECT (x).pg_sleep AS v FROM (SELECT 0.1::float8 AS x, 1 AS pg_sleep) x",
    ),
    (
        "disallowed_function",
        "SELECT (x).current_setting AS v FROM (SELECT 1 AS current_setting) x, (SELECT 'server_version'::text AS x) y",
    ),
    (
        "disallowed_function",
        "SELECT (x).current_setting AS v FROM (SELECT 'server_version'::text AS x, 1 AS current_setting) x(x, current_setting)",
    ),
    (
        "select_star",
        'SELECT s.to_jsonb FROM (SELECT id, g AS "To_Jsonb" FROM t) s',
    ),
    (
        "select_star",
        'SELECT s.to_jsonb FROM t AS s("To_Jsonb")',
    ),
    (
        "disallowed_function",
        'SELECT s.pg_typeof FROM t AS s("Pg_Typeof")',
    ),
    ("disallowed_table", 'WITH "Secret" AS (SELECT 1 AS id) SELECT id FROM secret'),
    (
        "disallowed_table",
        "WITH secret AS (SELECT id FROM secret) SELECT id FROM secret",
    ),
    (
        "disallowed_table",
        "WITH secret AS (SELECT 1 AS id) SELECT id FROM public.secret",
    ),
    ("select_star", 'WITH "T" AS (SELECT 1 AS to_jsonb) SELECT t.to_jsonb FROM t'),
    (
        "disallowed_function",
        "SELECT (s).pg_sleep AS v FROM (SELECT 1 AS pg_sleep, 0.01 AS s) s",
    ),
    ("parse_error", "SELECT ARRAY[1, 2][1] AS a"),
    ("parse_error", "SELECT json_object(ARRAY['a', 'b'][1:2]) AS a"),
    ("parse_error", "SELECT ARRAY(SELECT y FROM t ORDER BY id)[1] AS a"),
    ("parse_error", "SELECT INTERVAL(3) '1.5' SECOND AS a"),
    ("parse_error", "SELECT INTERVAL '1' DAY(3) AS a"),
    ("parse_error", "SELECT INTERVAL '1' DAY TO"),
    ("parse_error", "SELECT INTERVAL(3.0) '1.2' AS a"),
    ("parse_error", "SELECT INTERVAL(-1) '1 day' AS a"),
    ("parse_error", "SELECT INTERVAL(3) AS a"),
    ("parse_error", "SELECT INTERVAL '25 hours' DAY HOUR"),
    (
        "disallowed_function",
        "SELECT (tableoid).pg_relation_filepath AS v FROM t, (SELECT 1 AS pg_relation_filepath) tableoid",
    ),
    ("parse_error", "SELECT INTERVAL '1' \"Day\" AS v"),
    ("parse_error", "SELECT INTERVAL $$1$$ WEEK AS w"),
    ("parse_error", "SELECT INTERVAL '90.5 seconds' m\u0131nute AS v"),
    ("parse_error", "SELECT INTERVAL 5 DAY AS v"),
    ("parse_error", "SELECT INTERVAL 5::text AS v"),
    ("parse_error", "SELECT INTERVAL N'1' week AS v"),
    ("parse_error", "SELECT INTERVAL B'1' week AS v"),
    ("parse_error", "SELECT INTERVAL X'1' week AS v"),
    ("parse_error", "SELECT INTERVAL INTERVAL '1 day' AS v"),
    (
        "parse_error",
        "SELECT interval y '1' AS v FROM (SELECT id AS interval, y FROM t) s",
    ),
    # Infix `@` (no built-in operator since PostgreSQL 14): sqlglot cannot
    # read it beside an alias or in a condition. Without an alias, see
    # POSTGRES_REJECTS.
    ("parse_error", "SELECT y @ id AS v FROM t"),
    ("parse_error", "SELECT id FROM t WHERE y @ id"),
    # Review round 17: a precision before a field, a precision on a field
    # other than SECOND (Postgres's syntax errors), an empty subscript.
    ("parse_error", "SELECT '1.234'::interval(1) day to second AS a"),
    ("parse_error", "SELECT '1.234'::interval(1) day AS a"),
    ("parse_error", "SELECT '1'::interval minute(2) AS a"),
    ("parse_error", "SELECT interval[] AS v FROM (SELECT ARRAY[5] AS interval) s"),
    # Review round 18: an alias after an interval type where Postgres takes
    # none, or something after it (Postgres's syntax errors; they ran as an
    # `INTERVAL HOUR` / `MINUTE TO SECOND` / `WEEK` type before).
    ("parse_error", "SELECT CAST('1' AS interval h) AS a"),
    ("parse_error", "SELECT id FROM t WHERE iv < '1'::interval days"),
    ("parse_error", "SELECT '1'::interval min to sec AS a"),
    ("parse_error", "SELECT '{1}'::interval h[] AS a"),
    # Review round 19: an array type written twice or with a bound Postgres
    # does not take, an array type in a typed literal, a field word after a
    # type (an alias only after `AS`), a bare `array` alias.
    ("parse_error", "SELECT '{1}'::text[] array AS a"),
    ("parse_error", "SELECT '{1}'::text array[] AS a"),
    ("parse_error", "SELECT '{1}'::int[1.5] AS a"),
    ("parse_error", "SELECT int[] '{1}' AS a"),
    ("parse_error", "SELECT '{1}'::interval[] day"),
    ("parse_error", "SELECT '90'::\"interval\" day"),
    ("parse_error", "SELECT id array FROM t"),
    # The refused escape literal is the reason, though the text does not
    # parse either (`interval day '…'` is Postgres's syntax error).
    ("unsafe_literal", "SELECT interval day E'a\\b' AS v"),
    ("unsafe_literal", "SELECT interval U&'1' AS v"),
    # Review round 20: two operators inside `OPERATOR()` (sqlglot joined
    # them into one: `< =` ran as `<=`), or no operator name at all.
    ("parse_error", "SELECT id, y OPERATOR(pg_catalog.< =) 1 AS v FROM t"),
    ("parse_error", "SELECT id, g OPERATOR(pg_catalog.~ ~) 'a' AS v FROM t"),
    ("parse_error", "SELECT id, y OPERATOR(pg_catalog.+-) 1 AS v FROM t"),
    ("parse_error", "SELECT id, y OPERATOR('x') 1 AS v FROM t"),
]

# Need a newer Postgres than the oldest CI runs (see the module docstring).
MIN_SERVER_VERSION: dict[str, int] = {
    "SELECT id, regexp_count('aaa', 'a') AS c, regexp_substr('abc', 'b') AS s FROM t WHERE id = 1": 150000,
    "SELECT id, regexp_like(g, '^a') AS m FROM t ORDER BY id": 150000,
    "SELECT id, regexp_instr('abc', 'c') AS i FROM t WHERE id = 1": 150000,
    "SELECT id, regexp_like(g, 'B', 'i') AS a, regexp_count(g, 'a') AS b, regexp_instr(g, 'b') AS c, regexp_substr(g, '[a-z]') AS e FROM t ORDER BY id": 150000,
    "SELECT id, date_add(ts, INTERVAL '1 day', 'Asia/Tokyo') AS a, date_add(ts, INTERVAL '1 month') AS b FROM t ORDER BY id": 160000,
    "SELECT 0x1F, 0o17, 0b101": 160000,
    "SELECT 1_000": 160000,
    "SELECT 1_000.5_0 AS a, .5_0 AS b, 1e1_0 AS c, 0x1F + 1 AS e, -0b11 AS f FROM t WHERE id = 0x1F": 160000,
    "SELECT id FROM t ORDER BY id LIMIT 0x3": 160000,
    "SELECT json_object(key VALUE id) AS a, json_object(\"KEY\" VALUE id) AS b, json_object(s.key: s.id) AS c FROM (SELECT 'k' AS key, 'K' AS \"KEY\", id FROM t WHERE id < 3) s ORDER BY id": 160000,
    "SELECT json_object('a' VALUE NULL ABSENT ON NULL) AS a, json_object('a' VALUE 1 RETURNING jsonb) AS b, json_object('k': '{\"x\": 1}' FORMAT JSON) AS c, json_object('a' VALUE id) AS e FROM t WHERE id < 3 ORDER BY id": 160000,
}

# Accepted and run as written; Postgres itself rejects them.
POSTGRES_REJECTS: list[str] = [
    "SELECT id FROM t ORDER BY id LIMIT -1",
    "SELECT id, initcap(g, '-') AS i FROM t ORDER BY id",
    "SELECT id, to_number(g) AS n FROM t WHERE id = 1",
    'SELECT "Lower"(g) FROM t',
    'SELECT g::"Text" FROM t',
    'SELECT x::"Numeric"(10, 2) FROM t',
    'SELECT x::"int" FROM t',
    "SELECT nvl(g, 'z') FROM t",
    "SELECT id, array_length(arr) FROM t",
    "SELECT last_day(d) FROM t",
    "SELECT now(3)",
    "SELECT current_timestamp(0, 1)",
    "SELECT percentile_cont(x, 0.5) FROM t",
    "SELECT g, string_agg(g, ',') WITHIN GROUP (ORDER BY g) FROM t GROUP BY g",
    "SELECT id FROM t ORDER BY id LIMIT 'NaN'::float8",
    "SELECT id FROM t ORDER BY id LIMIT '3'::text",
    "SELECT id FROM t ORDER BY id LIMIT 99999999999999999999",
    "SELECT ~2 ^ 2 AS a",
    "SELECT t.text AS v FROM t LIMIT 1",
    "SELECT json_object(g, value + 1) AS o FROM t WHERE id = 1",
    "SELECT id, x IS NOT DISTINCT FROM 1.37 IS TRUE AS a FROM t ORDER BY id",
    "SELECT id, x IS NOT DISTINCT FROM 1.37 IS NOT TRUE AS a FROM t ORDER BY id",
    "SELECT id, x IS NOT DISTINCT FROM 1.37 IS NULL AS a FROM t ORDER BY id",
    "SELECT id, x IS NOT DISTINCT FROM 1.37 IS NOT NULL AS a FROM t ORDER BY id",
    "SELECT id, x IS NOT DISTINCT FROM 1.37 IS FALSE AS a FROM t ORDER BY id",
    "SELECT id, x IS NOT DISTINCT FROM 1.37 IS NOT FALSE AS a FROM t ORDER BY id",
    "SELECT id, x IS NOT DISTINCT FROM 1.37 = true AS a FROM t ORDER BY id",
    "SELECT id, x IS NOT DISTINCT FROM 1.37 <> false AS a FROM t ORDER BY id",
    "SELECT id, x IS NOT DISTINCT FROM 1.37 IS DISTINCT FROM true AS a FROM t ORDER BY id",
    "SELECT id, x IS NOT DISTINCT FROM 1.37 IS NOT DISTINCT FROM NULL AS a FROM t ORDER BY id",
    "SELECT id, x IS DISTINCT FROM 1.37 IS TRUE AS a FROM t ORDER BY id",
    "SELECT id, x IS DISTINCT FROM 1.37 IS NOT TRUE AS a FROM t ORDER BY id",
    "SELECT id, x IS DISTINCT FROM 1.37 IS NULL AS a FROM t ORDER BY id",
    "SELECT id, x IS DISTINCT FROM 1.37 IS NOT NULL AS a FROM t ORDER BY id",
    "SELECT id, x IS DISTINCT FROM 1.37 IS FALSE AS a FROM t ORDER BY id",
    "SELECT id, x IS DISTINCT FROM 1.37 IS NOT FALSE AS a FROM t ORDER BY id",
    "SELECT id, x IS DISTINCT FROM 1.37 = true AS a FROM t ORDER BY id",
    "SELECT id, x IS DISTINCT FROM 1.37 <> false AS a FROM t ORDER BY id",
    "SELECT id, x IS DISTINCT FROM 1.37 IS DISTINCT FROM true AS a FROM t ORDER BY id",
    "SELECT id, x IS DISTINCT FROM 1.37 IS NOT DISTINCT FROM NULL AS a FROM t ORDER BY id",
    "SELECT id, y > 2 = true AS a FROM t ORDER BY id",
    "SELECT id, y > 2 <> false AS a FROM t ORDER BY id",
    "SELECT id, y = 1 = true AS a FROM t ORDER BY id",
    "SELECT id, y = 1 <> false AS a FROM t ORDER BY id",
    "SELECT id, j ->> 'k'::int AS a FROM t WHERE id = 99",
    "SELECT id, x IS NOT DISTINCT FROM y IS TRUE AS a FROM t ORDER BY id",
    "SELECT id, x IS DISTINCT FROM y IS NOT TRUE AS a FROM t ORDER BY id",
    "SELECT id FROM t ORDER BY id LIMIT 'Infinity'::float8",
    "SELECT 4 ^@ 2 AS v",
    'SELECT "USER" FROM t',
    "SELECT id FROM t ORDER BY id LIMIT '5\u00a0'",
    "SELECT ! true AS v",
    "SELECT id FROM t WHERE id = $1",
    "SELECT id FROM t WHERE id = $1::int",
    "SELECT id FROM t WHERE g = $name",
    "SELECT INTERVAL '1' SECOND(3) TO SECOND",
    "SELECT id FROM t ORDER BY id LIMIT (SELECT 'NaN'::float8)",
    "SELECT id FROM t ORDER BY id LIMIT ((SELECT 'Infinity'::float8 AS i))",
    "SELECT id FROM t ORDER BY id LIMIT (SELECT 'NaN'::numeric FROM t WHERE id = 1)",
    "SELECT INTERVAL '1 day'', g, ''b' FROM t",
    "SELECT INTERVAL '1 day' + 2 AS v",
    # sqlglot reads `y` with the alias `@ id` and renders `y AS @ id`, a
    # syntax error; Postgres has no `integer @ integer`.
    "SELECT y @ id FROM t",
    # A subscript with a stride (Postgres has none), as written.
    "SELECT x[1:2:3] AS v FROM (SELECT ARRAY[5] AS x) s",
    "SELECT interval[1:2:3] AS v FROM (SELECT ARRAY[5] AS interval) s",
    # `OPERATOR()` as written: a quoted qualifier stays quoted (no schema
    # "PG_CATALOG"; it ran as `pg_catalog.+`), no such operator / schema.
    'SELECT id, y OPERATOR("PG_CATALOG".+) 1 AS v FROM t',
    "SELECT id, x OPERATOR(pg_catalog.==) 2 AS v FROM t",
    "SELECT id, x OPERATOR(nosuchschema.+) 1 AS v FROM t",
    "SELECT id, y OPERATOR(McpOps.=) 'a' AS v FROM t",
    "SELECT id, !~ x AS v FROM t",
    # A quoted type name is the name as written (no such types): sqlglot
    # ran `"bit varying"` as `varbit` and `"int array"` as `"int array"[]`.
    "SELECT '101'::\"bit varying\" AS v",
    'SELECT id, CAST(g AS "bit varying") AS v FROM t',
    "SELECT '{101}'::\"bit varying\"[] AS v",
    "SELECT '{1}'::\"int array\" AS v",
    "SELECT '{1}'::\"int[]\" AS v",
]
