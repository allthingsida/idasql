-- Recursive CTE: Find all call chains starting from a function
-- Shows caller -> callee relationships with depth tracking
WITH RECURSIVE call_chain(root_func, caller, callee, depth, path) AS (
    -- Base case: direct calls from root functions
    SELECT
        func_addr as root_func,
        func_addr as caller,
        callee_addr as callee,
        1 as depth,
        printf('0x%X', func_addr) as path
    FROM disasm_calls
    WHERE callee_addr IS NOT NULL

    UNION ALL

    -- Recursive case: follow callee's calls
    SELECT
        cc.root_func,
        dc.func_addr as caller,
        dc.callee_addr as callee,
        cc.depth + 1,
        cc.path || ' -> ' || printf('0x%X', dc.func_addr)
    FROM call_chain cc
    JOIN disasm_calls dc ON dc.func_addr = cc.callee
    WHERE cc.depth < 5  -- Limit recursion depth
      AND dc.callee_addr IS NOT NULL
)
SELECT
    printf('0x%X', root_func) as root,
    depth,
    path,
    printf('0x%X', callee) as final_callee
FROM call_chain
ORDER BY root_func, depth
LIMIT 50;
