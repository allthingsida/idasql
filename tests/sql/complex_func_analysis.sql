-- Complex function analysis: size, blocks, callers
SELECT
    printf('0x%08X', f.address) as addr,
    f.name,
    f.size,
    COALESCE(bc.block_count, 0) as blocks,
    COALESCE(xc.caller_count, 0) as callers,
    CASE
        WHEN f.size < 16 THEN 'tiny'
        WHEN f.size < 64 THEN 'small'
        WHEN f.size < 256 THEN 'medium'
        WHEN f.size < 1024 THEN 'large'
        ELSE 'huge'
    END as size_class
FROM funcs f
LEFT JOIN (
    SELECT func_ea, COUNT(*) as block_count
    FROM blocks
    GROUP BY func_ea
) bc ON f.address = bc.func_ea
LEFT JOIN (
    SELECT to_ea, COUNT(*) as caller_count
    FROM xrefs
    WHERE is_code = 1
    GROUP BY to_ea
) xc ON f.address = xc.to_ea
ORDER BY f.size DESC
LIMIT 20;
