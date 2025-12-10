-- Named locations that are NOT function starts
SELECT
    printf('0x%08X', n.address) as addr,
    n.name
FROM names n
WHERE n.address NOT IN (SELECT address FROM funcs)
LIMIT 20;
