-- Top 10 largest functions by size
SELECT
    printf('0x%08X', address) as addr,
    name,
    size
FROM funcs
ORDER BY size DESC
LIMIT 10;
