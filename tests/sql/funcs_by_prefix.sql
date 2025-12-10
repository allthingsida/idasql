-- Functions matching a name prefix
-- Parameters: ${prefix}
SELECT
    printf('0x%08X', address) as addr,
    name,
    size
FROM funcs
WHERE name LIKE '${prefix}%'
ORDER BY name
LIMIT 20;
