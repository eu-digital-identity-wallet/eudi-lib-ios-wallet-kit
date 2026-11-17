import Testing

/// These suites share process-wide metadata caches. Serialize them together so
/// one suite cannot invalidate another suite's cache-hit or request-count checks.
/// Task groups inside the concurrency tests still exercise parallel cache access.
@Suite("OpenID4VCI shared metadata caches", .serialized)
struct MetadataCacheTests {
    @Suite struct AuthorizationServerMetadataCacheTests {}
    @Suite("Issuer of a deferred credential request") struct DeferredIssuerMetadataTests {}
    @Suite struct MetadataCacheConcurrencyTests {}
    @Suite("OpenID4VCI service utility coverage") struct VciServiceUtilityCoverageTests {}
}
