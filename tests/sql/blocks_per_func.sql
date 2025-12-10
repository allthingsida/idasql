-- Basic blocks per function (top 10 most complex)
SELECT
    printf('0x%08X', b.func_ea) as func,
    f.name,
    COUNT(*) as block_count,
    SUM(b.size) as total_size
FROM blocks b
JOIN funcs f ON b.func_ea = f.address
GROUP BY b.func_ea
ORDER BY block_count DESC
LIMIT 10;
