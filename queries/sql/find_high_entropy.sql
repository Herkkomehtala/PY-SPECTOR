-- Find files with a high average entropy.
-- This is a strong indicator of packed or encrypted data
-- A threshold of 7.5+ is anomalous

SELECT
    path,
    avg_entropy,
    company_name,
    product_name
FROM
    binaries
WHERE
    avg_entropy > 7.5
ORDER BY
    avg_entropy DESC;