-- Find files with a high-entropy .text section.
-- The .text section contains executable code and should
-- have mid-range entropy. High entropy (> 7.0) means
-- the code itself is packed or encrypted (like with UPX).
--
-- Requires SQLite with the JSON1 extension enabled.

SELECT
    b.path,
    json_extract(j.value, '$.entropy') AS text_entropy,
    b.product_name
FROM
    binaries b,
    json_each(b.section_entropy_json) j
WHERE
    json_extract(j.value, '$.name') = '.text'
    AND json_extract(j.value, '$.entropy') > 7.0
ORDER BY
    text_entropy DESC;