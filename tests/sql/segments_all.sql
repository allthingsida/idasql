-- List all segments with details
SELECT
    printf('0x%08X', start_ea) as start,
    printf('0x%08X', end_ea) as end,
    name,
    class,
    perm,
    (end_ea - start_ea) as size
FROM segments
ORDER BY start_ea;
