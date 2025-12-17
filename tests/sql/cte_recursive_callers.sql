-- Recursive CTE: Find all functions that eventually call a target
-- (reverse call chain - who calls the callers?)
WITH RECURSIVE reverse_chain(target, caller, depth) AS (
    -- Base: direct callers of functions
    SELECT
        callee_addr as target,
        func_addr as caller,
        1 as depth
    FROM disasm_calls
    WHERE callee_addr IS NOT NULL

    UNION ALL

    -- Recursive: callers of callers
    SELECT
        rc.target,
        dc.func_addr as caller,
        rc.depth + 1
    FROM reverse_chain rc
    JOIN disasm_calls dc ON dc.callee_addr = rc.caller
    WHERE rc.depth < 4
)
SELECT
    printf('0x%X', target) as target_func,
    COUNT(DISTINCT caller) as unique_callers,
    MAX(depth) as max_depth
FROM reverse_chain
GROUP BY target
HAVING COUNT(DISTINCT caller) > 2
ORDER BY unique_callers DESC
LIMIT 20;
