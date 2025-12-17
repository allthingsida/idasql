-- Nested subqueries: Find functions larger than average that are called more than average
SELECT
    printf('0x%X', f.start_ea) as addr,
    f.name,
    f.size,
    (SELECT COUNT(*) FROM xrefs x WHERE x.to_ea = f.start_ea AND x.is_code = 1) as call_count
FROM funcs f
WHERE f.size > (SELECT AVG(size) FROM funcs)
  AND (SELECT COUNT(*) FROM xrefs x WHERE x.to_ea = f.start_ea AND x.is_code = 1) >
      (SELECT AVG(cnt) FROM (SELECT COUNT(*) as cnt FROM xrefs WHERE is_code = 1 GROUP BY to_ea))
ORDER BY call_count DESC
LIMIT 15;
