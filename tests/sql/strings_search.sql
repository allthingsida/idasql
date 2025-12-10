-- Search strings containing pattern
-- Parameters: ${pattern}
SELECT
    printf('0x%08X', address) as addr,
    length,
    content
FROM strings
WHERE content LIKE '%${pattern}%'
ORDER BY address
LIMIT 20;
