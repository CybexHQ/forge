-- Record *why* a managed build job was refused as an enumerated code, not only
-- as prose.
--
-- Manage runs reported free text through a heuristic that blanks the whole
-- value when it spots words like "credential", "secret", or "password" -- the
-- exact vocabulary every protected-material rejection uses. The reason reached
-- Manage as "[redacted]", which tells an operator nothing. A code drawn from a
-- closed set cannot carry tenant data, so Manage can render it verbatim
-- without guessing.
ALTER TABLE james_build_jobs ADD COLUMN rejection_code TEXT NOT NULL DEFAULT '';
