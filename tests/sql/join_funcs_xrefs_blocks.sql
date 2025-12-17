-- Complex JOIN: Functions with their callers, callees, and block counts
SELECT
    printf('0x%X', f.start_ea) as func_addr,
    f.name as func_name,
    f.size,
    (SELECT COUNT(*) FROM blocks b WHERE b.func_ea = f.start_ea) as block_count,
    (SELECT COUNT(*) FROM xrefs x WHERE x.to_ea = f.start_ea AND x.is_code = 1) as caller_count,
    (SELECT COUNT(*) FROM xrefs x WHERE x.from_ea >= f.start_ea AND x.from_ea < f.end_ea AND x.is_code = 1) as callee_count
FROM funcs f
WHERE f.size > 16
ORDER BY caller_count DESC, f.size DESC
LIMIT 25;
