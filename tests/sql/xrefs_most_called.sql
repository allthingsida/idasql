-- Top 10 most called functions
SELECT
    printf('0x%08X', f.address) as addr,
    f.name,
    COUNT(*) as caller_count
FROM funcs f
JOIN xrefs x ON f.address = x.to_ea
WHERE x.is_code = 1
GROUP BY f.address
ORDER BY caller_count DESC
LIMIT 10;
