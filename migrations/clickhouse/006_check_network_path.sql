-- What an HTTP probe saw on the way to a result that was not up. IPv4 is
-- stored IPv4-mapped.
ALTER TABLE check_results
    ADD COLUMN IF NOT EXISTS remote_ip Nullable(IPv6) CODEC(ZSTD(1)) AFTER response_size;

ALTER TABLE check_results
    ADD COLUMN IF NOT EXISTS tried_ips Array(IPv6) CODEC(ZSTD(1)) AFTER remote_ip;

ALTER TABLE check_results
    ADD COLUMN IF NOT EXISTS hop_url Nullable(String) CODEC(ZSTD(1)) AFTER tried_ips;

ALTER TABLE check_results
    ADD COLUMN IF NOT EXISTS dns_resolver Nullable(IPv6) CODEC(ZSTD(1)) AFTER hop_url;

ALTER TABLE check_results
    ADD COLUMN IF NOT EXISTS dns_answer Array(IPv6) CODEC(ZSTD(1)) AFTER dns_resolver;

ALTER TABLE check_results
    ADD COLUMN IF NOT EXISTS dns_ttl Nullable(UInt32) CODEC(ZSTD(1)) AFTER dns_answer;
