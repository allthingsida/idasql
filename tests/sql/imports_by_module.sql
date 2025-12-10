-- Imports grouped by module
SELECT
    module,
    COUNT(*) as import_count
FROM imports
GROUP BY module
ORDER BY import_count DESC;
