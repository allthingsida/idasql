-- CTE: Find leaf functions (functions that don't call other functions)
WITH callers AS (
    SELECT DISTINCT func_addr
    FROM disasm_calls
    WHERE callee_addr IS NOT NULL
)
SELECT
    printf('0x%X', f.start_ea) as addr,
    f.name,
    f.size
FROM funcs f
LEFT JOIN callers c ON f.start_ea = c.func_addr
WHERE c.func_addr IS NULL
ORDER BY f.size DESC
LIMIT 20;
