# Registration Certificate

Validate the Wallet-Relying Party Registration Certificate (WRPRC) that a relying party presents with a data-sharing request, or that a credential issuer publishes with its metadata.

## Overview

A WRPRC is a signed JWT or CWT issued by a registration-certificate provider (per [ETSI TS 119 475](https://www.etsi.org/standards)). It describes the relying party's registered identity, intended use, and the claims it is registered to request or the attestations it is registered to provide. It is distinct from the access certificate (WRPAC) — the X.509 e-seal that authenticates the request itself — and is bound to it.

The wallet validates the certificate and surfaces the outcome so the application can inform the user before sharing or accepting credentials. This satisfies two obligations of ETSI TS 119 472-2 clause 4.4 and Commission Implementing Regulation (EU) 2025/848 Article 8(2):

- **WRP-VALIDATION-02** — warn the user when the certificate cannot be validated.
- **WRP-OVERASKING-02** — warn the user when the request asks for attributes outside the registered scope.

The certificate is carried differently depending on the channel:

| Channel | Carrier |
|---|---|
| Proximity presentation (ISO/IEC 18013-5) | `euWrprc` byte string in each `ItemsRequest` `requestInfo` (ETSI TS 119 472-2 §5.3.2) |
| Remote presentation (OpenID4VP) | `verifier_info` element with `format = "registration_cert"` (ETSI TS 119 472-2 §6.3.2.2) |
| Issuance (OpenID4VCI) | `registration_cert` entry in the `issuer_info` of the signed issuer metadata (CIR 2024/2082) |

Two validators cover the two directions:

- ``WrpVpRegistrationValidator`` — validates the **verifier** (relying party) WRPRC during presentation (OpenID4VP and BLE proximity).
- ``WrpVciRegistrationValidator`` — validates the **issuer** WRPRC during OpenID4VCI issuance.

## Configuration

### Enabling registration certificate validation

For **OpenID4VP** requests, set ``OpenId4VpConfiguration/validateRegistrationCertificate`` (enabled by default). The WRPRC is validated by ``WrpVpRegistrationValidator`` using the wallet trust configuration.

```swift
let openId4VpConfig = OpenId4VpConfiguration(
    clientIdSchemes: [.x509SanDns],
    validateRegistrationCertificate: true // default
)
```

For **BLE proximity** requests, the ``WrpVpRegistrationValidator`` is created from the wallet's ``TrustConfiguration`` and used internally by ``BlePresentationService``.

For **OpenID4VCI issuance**, set ``OpenId4VciConfiguration/validateRegistrationCertificate`` (disabled by default). It requires ``OpenId4VciConfiguration/issuerMetadataPolicy`` to be `.requireSigned`, since WRPRC enforcement needs a cryptographically bound issuer metadata signer to supply the WRPAC.

```swift
let vciConfig = OpenId4VciConfiguration(
    credentialIssuerURL: "https://issuer.example.com",
    keyAttestationsConfig: keyAttestationsConfig,
    issuerMetadataPolicy: trustConfig.issuerMetadataPolicy, // .requireSigned
    validateRegistrationCertificate: true
)
```

### Trust anchors

The ``TrustConfiguration`` supplies the trust material for WRPRC validation:

- **``TrustConfiguration/registrationTrustManager``** — validates the certificate's signer chain (the registration-certificate provider's e-seal). Derived from the trust source with the WRPRC verification context.
- **Status-list trust** — validates the status-list token used for the revocation check, also resolved through the trust configuration.

```swift
let trustConfig = TrustConfiguration(
    trustSource: .etsi(.eudiRef),
    fallbackTrustSource: nil,
    wrprcTrustPolicy: .enforce // default; use .warning to downgrade failures to warnings
)
let wallet = try EudiWallet(
    eudiWalletConfig: config,
    trustConfig: trustConfig,
    openID4VpConfig: openId4VpConfig
)
```

### Trust policy

``TrustConfiguration/wrprcTrustPolicy`` controls the behaviour when a validation check fails:

- **`.enforce`** (default) — a failed check causes the request to fail with ``WalletError/Code/invalidWrprc``.
- **`.warning`** — a failed check is added to the warnings list and the request continues.

## Validation flow

Both validators share the same core token validation, followed by a flow-specific scope check:

### 1. Authentication

Parses the certificate (JWT or CWT), verifies its signature, and checks that the signer chain is trusted against the ``TrustConfiguration/registrationTrustManager``. This stage cannot be replaced.

### 2. Evaluation

Checks the authenticated registration against the request or offer:

| Check | Failure | Reference |
|---|---|---|
| **Binding** — the certificate `sub` (or intermediary) matches the access certificate subject | Warning: "WRPRC not bound to requester access certificate" | ETSI TS 119 475 §4.5, §5.1.1 |
| **Expiry** — the `exp` claim has not passed | ``WalletError/Code/wrprcExpired`` | ETSI TS 119 475 §5.2.4 |
| **Status reference** — the certificate carries a status-list reference | ``WalletError/Code/wrprcMissingStatus`` | ETSI TS 119 475 §6.2.6.2 |
| **Revocation** — the status list reports the certificate as valid | ``WalletError/Code/wrprcStatusInvalid`` | ETSI TS 119 475 §6.2.6.2 |
| **Trust** — the signer chain is trusted | ``WalletError/Code/wrprcTrustError`` | WRP-VALIDATION-02 |
| **Scope (presentation)** — the requested claims stay within the registered scope | `PolicyViolation` warnings | WRP-OVERASKING-02 |
| **Scope (issuance)** — the offered credential configurations are covered by the registered `provides_attestations` | `PolicyViolation` warnings | CIR 2024/2082 |

Warnings are collected in a dictionary keyed by credential query/configuration identifier; the empty key holds request-wide warnings.

## Reading the outcome — presentation

The result is exposed on ``PresentationSession`` via two `@Published` properties:

- ``PresentationSession/wrpVerifierPolicy`` — the parsed ``WrpRegistrationPolicy`` when authentication succeeds. Contains the relying party's name, country, purpose, registered credentials, and other metadata.
- ``PresentationSession/wrpVerifierWarnings`` — validation warnings keyed by credential query identifier; the empty key holds request-wide warnings, including over-asked claims.

```swift
struct ShareView: View {
    @ObservedObject var session: PresentationSession

    var body: some View {
        if let registration = session.wrpVerifierPolicy {
            Text(registration.name ?? registration.sub)

            if let warnings = session.wrpVerifierWarnings?[""], !warnings.isEmpty {
                ForEach(warnings, id: \.self) { warning in
                    Label(warning.description, systemImage: "exclamationmark.triangle")
                }
            }
        }
    }
}
```

### Per-option warnings via DisclosedDocumentSet

When DCQL resolution produces multiple credential selection options, each ``DisclosedDocumentSet`` in ``PresentationSession/disclosedDocumentSets`` carries its own `warnings` array. These per-option `PolicyViolation` values indicate over-asked claims specific to that credential combination — for example, one option may request claims outside the registered scope while another stays within it.

```swift
for option in session.disclosedDocumentSets {
    if let warnings = option.warnings, !warnings.isEmpty {
        // This credential combination has policy violations — warn the user
    }
}
```

### Validity and scope are two separate results

A valid certificate can still be over-asking. Check **both** ``PresentationSession/wrpVerifierPolicy`` and ``PresentationSession/wrpVerifierWarnings`` (for session-level warnings), as well as each ``DisclosedDocumentSet/warnings`` (for per-option warnings):

- `wrpVerifierPolicy != nil` **and** no warnings → valid and within scope.
- `wrpVerifierPolicy != nil` **and** warnings present → valid but over-asking or has other warnings; warn the user.
- `wrpVerifierPolicy == nil` → no certificate was present, or validation failed (with `.enforce` policy).

## Reading the outcome — issuance

``EudiWallet/issueDocuments(issuerName:docTypeIdentifiers:credentialOptions:keyOptions:promptMessage:)`` and ``EudiWallet/issueDocumentsByOfferUrl(offerUri:docTypes:txCodeValue:promptMessage:configuration:)`` return an ``IssuerResponse`` that pairs the issued documents with the WRPRC outcome:

- ``IssuerResponse/wrpIssuerPolicy`` — the parsed ``WrpRegistrationPolicy`` of the issuer, including the attestations it is registered to provide.
- ``IssuerResponse/wrpIssuerWarnings`` — warnings keyed by credential configuration identifier; the empty key holds request-wide warnings. `nil` when validation is not enabled.
- ``IssuerResponse/documentWarnings`` — the same warnings matched to each issued document by its credential configuration identifier, keyed by document identifier.

```swift
let response = try await wallet.issueDocumentsByOfferUrl(offerUri: offerUri, docTypes: docTypes)
if let issuerRegistration = response.wrpIssuerPolicy {
    // Show issuer info: issuerRegistration.name, issuerRegistration.country
}
for (documentId, warnings) in response.documentWarnings {
    // Warn the user about registration policy violations for this document
}
```

## WrpRegistrationPolicy

The ``WrpRegistrationPolicy`` struct carries the decoded registration certificate payload:

| Property | Type | Description |
|---|---|---|
| `sub` | `String` | Registered relying party identifier |
| `name` | `String?` | Display name |
| `country` | `String?` | Country of registration |
| `purpose` | `[PolicyPurpose]?` | Localized purpose descriptions |
| `credentials` | `[PolicyCredential]?` | Attestations and claims the RP is registered to request |
| `providesAttestations` | `[PolicyCredential]?` | Attestations the issuer is registered to provide |
| `exp` | `Int?` | Expiration timestamp |
| `status` | `Status?` | Status-list reference for revocation |
| `intermediary` | `PolicyIntermediary?` | Intermediary details when the RP acts through one |
| `supervisoryAuthority` | `SupervisoryAuthority?` | Supervisory authority contact |
| `privacyPolicy` | `String?` | Privacy policy URI |
| `registryURI` | `String?` | Registry URI |

## Topics

### Validation

- ``WrpVpRegistrationValidator``
- ``WrpVciRegistrationValidator``
- ``WrpRegistrationPolicy``

### Configuration

- ``OpenId4VpConfiguration``
- ``OpenId4VciConfiguration``
- ``TrustConfiguration``

### Result

- ``PresentationSession/wrpVerifierPolicy``
- ``PresentationSession/wrpVerifierWarnings``
- ``DisclosedDocumentSet``
- ``PresentationSession/disclosedDocumentSets``
- ``IssuerResponse``
