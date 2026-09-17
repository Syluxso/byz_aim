ALTER TABLE iam.users
    ADD COLUMN IF NOT EXISTS first_name VARCHAR(255),
    ADD COLUMN IF NOT EXISTS last_name VARCHAR(255);

UPDATE iam.users
SET
    first_name = CASE
        WHEN position(' ' IN btrim(name)) > 0 THEN split_part(btrim(name), ' ', 1)
        ELSE NULLIF(btrim(name), '')
    END,
    last_name = CASE
        WHEN position(' ' IN btrim(name)) > 0
            THEN NULLIF(btrim(substring(btrim(name) FROM position(' ' IN btrim(name)) + 1)), '')
        ELSE NULL
    END
WHERE first_name IS NULL AND last_name IS NULL;
