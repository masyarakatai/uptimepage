-- What a certificate, DNS or domain check read, on up results too: the
-- tagged `CheckDetails` document as JSON.
ALTER TABLE check_results
    ADD COLUMN IF NOT EXISTS details Nullable(String) CODEC(ZSTD(1)) AFTER error;
