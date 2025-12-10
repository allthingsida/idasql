-- Bottom 10 least called functions (including uncalled)
SELECT
    printf('0x%08X', f.address) as addr,
    f.name,
    COUNT(x.from_ea) as caller_count
FROM funcs f
LEFT JOIN xrefs x ON f.address = x.to_ea AND x.is_code = 1
GROUP BY f.address
ORDER BY caller_count ASC
LIMIT 10;
