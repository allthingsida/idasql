-- Multi-table JOIN: Functions in code segments with their strings
SELECT
    printf('0x%X', f.start_ea) as func,
    f.name,
    s.name as segment,
    (SELECT COUNT(*) FROM strings str
     WHERE str.ea >= f.start_ea AND str.ea < f.end_ea) as string_count
FROM funcs f
JOIN segments s ON f.start_ea >= s.start_ea AND f.start_ea < s.end_ea
WHERE s.perm & 1 = 1  -- Executable segment
ORDER BY string_count DESC, f.size DESC
LIMIT 20;
