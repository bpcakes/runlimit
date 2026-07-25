WITH authoritative_time AS MATERIALIZED (
    SELECT pg_catalog.clock_timestamp() AS sampled_at
)
DELETE FROM runlimit_fixed_windows AS windows
USING (
    SELECT ctid
    FROM runlimit_fixed_windows
    -- The scalar subquery becomes an init-plan parameter, allowing the expiry
    -- index to stop before active windows instead of filtering its full scan.
    WHERE window_expires_at <= (
        SELECT sampled_at
        FROM authoritative_time
    )
    ORDER BY window_expires_at
    FOR UPDATE SKIP LOCKED
    LIMIT $1
) AS expired
WHERE windows.ctid = expired.ctid
