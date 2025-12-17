-- CTE: Comprehensive function metrics combining multiple tables
WITH
func_calls AS (
    SELECT func_addr, COUNT(*) as call_count
    FROM disasm_calls
    GROUP BY func_addr
),
func_xrefs_to AS (
    SELECT to_ea, COUNT(*) as refs_to
    FROM xrefs
    WHERE is_code = 1
    GROUP BY to_ea
),
func_xrefs_from AS (
    SELECT from_ea, COUNT(*) as refs_from
    FROM xrefs
    WHERE is_code = 1
    GROUP BY from_ea
),
func_blocks AS (
    SELECT func_ea, COUNT(*) as block_count
    FROM blocks
    GROUP BY func_ea
)
SELECT
    printf('0x%X', f.start_ea) as addr,
    f.name,
    f.size,
    COALESCE(fb.block_count, 0) as blocks,
    COALESCE(fc.call_count, 0) as calls_made,
    COALESCE(xt.refs_to, 0) as called_by,
    COALESCE(xf.refs_from, 0) as refs_out,
    CASE
        WHEN COALESCE(xt.refs_to, 0) = 0 THEN 'entry_point'
        WHEN COALESCE(fc.call_count, 0) = 0 THEN 'leaf'
        ELSE 'internal'
    END as func_type
FROM funcs f
LEFT JOIN func_blocks fb ON f.start_ea = fb.func_ea
LEFT JOIN func_calls fc ON f.start_ea = fc.func_addr
LEFT JOIN func_xrefs_to xt ON f.start_ea = xt.to_ea
LEFT JOIN func_xrefs_from xf ON f.start_ea = xf.from_ea
ORDER BY f.size DESC
LIMIT 30;
