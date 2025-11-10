-- Find files that are missing basic version information.
-- Legitimate software almost always has a Company,
-- Product, and Description.

SELECT
    path,
    avg_entropy,
    product_name,
    company_name,
    file_description
FROM
    binaries
WHERE
    company_name IS NULL
    OR file_description IS NULL
    OR product_name IS NULL
ORDER BY
    avg_entropy DESC;