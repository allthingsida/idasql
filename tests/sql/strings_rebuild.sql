-- Test rebuild_strings function
-- Rebuilds string list using current IDA settings

-- Rebuild the string list
SELECT 'rebuilding' as status, rebuild_strings() as count;

-- Check count without rebuild
SELECT 'current_count' as status, string_count() as count;
