-- Test strings table columns including new decoded fields
-- Shows string type breakdown with all columns

-- Rebuild strings first (uses current IDA settings)
SELECT rebuild_strings() as total_strings;

-- Count strings by type_name
SELECT
    type_name,
    layout_name,
    width_name,
    COUNT(*) as count
FROM strings
GROUP BY type_name, layout_name, width_name
ORDER BY count DESC;

-- Show sample strings with all columns
SELECT
    printf('0x%08X', address) as addr,
    length,
    type,
    type_name,
    width,
    width_name,
    layout,
    layout_name,
    encoding,
    substr(content, 1, 40) as content_preview
FROM strings
ORDER BY address
LIMIT 10;

-- String statistics
SELECT
    'total' as metric,
    COUNT(*) as value
FROM strings
UNION ALL
SELECT
    'ascii_count',
    COUNT(*)
FROM strings WHERE type_name = 'ascii'
UNION ALL
SELECT
    'utf16_count',
    COUNT(*)
FROM strings WHERE type_name = 'utf16'
UNION ALL
SELECT
    'utf32_count',
    COUNT(*)
FROM strings WHERE type_name = 'utf32';
