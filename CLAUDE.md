# CLAUDE.md — EudiWalletKit

## What This Is

iOS/macOS Swift library that coordinates EUDI wallet components: document storage, issuance (OpenID4VCI), and presentation (OpenID4VP, ISO 18013-5 BLE). It's the orchestration layer — not a standalone app.

## Build & Test

```bash
swift build
swift test
```

Requires Xcode (latest) on macOS. Swift 6.0+, targets iOS 16+, macOS 14+, watchOS 10+.

CI runs on GitHub Actions (`swift.yml`) — builds and tests on `macos-latest`.

## Project Layout

```
Sources/EudiWalletKit/
  EudiWallet.swift          # Main entry point, ObservableObject for SwiftUI
  EudiWalletKit.swift       # Package-level logger setup
  Extensions.swift
  Models/
    EudiWalletConfiguration.swift   # Wallet settings
    OpenId4VCIConfiguration.swift   # Issuer config (DPoP, attestation)
    OpenId4VpConfiguration.swift    # Verifier config
    WalletError.swift               # Localized errors
    DocElements.swift               # Document element definitions
    OfferedIssuanceModel.swift      # Issuance offer models
    KeyAttestationConfiguration.swift
    Enums.swift
    InternalssuanceModels.swift     # (note: typo in filename is intentional)
  Services/
    StorageManager.swift            # Document storage, @Published properties
    OpenId4VciService.swift         # Credential issuance (actor)
    OpenId4VpService.swift          # Remote presentation
    BlePresentationService.swift    # BLE proximity presentation
    PresentationService.swift       # Abstract presentation protocol
    PresentationSession.swift       # Session management
    FaultPresentationService.swift  # Error handling for presentations
    SecureAreaSigner.swift          # Crypto signing with secure areas
    DocumentStatusService.swift     # Document lifecycle
    TransactionLog.swift            # Audit logging
    DcqlQueryable.swift             # DCQL query support
    Openid4VpUtils.swift
    TransactionLogUtils.swift
    Enumerations.swift
  EudiWalletKit.docc/              # DocC documentation catalog

Tests/EudiWalletKitTests/
  EudiWalletKitTests.swift
  DcqlQueryTests.swift
  Resources/                        # JSON, CBOR, JWT test fixtures
```

## Dependencies (SPM, pinned versions)

| Package | What it does |
|---------|-------------|
| `eudi-lib-ios-wallet-storage` 0.8.4 | Encrypted document storage (Keychain) |
| `eudi-lib-ios-iso18013-data-transfer` 0.8.5 | ISO 18013-5 BLE data transfer |
| `eudi-lib-ios-openid4vci-swift` 0.20.0 | OpenID4VCI credential issuance |
| `eudi-lib-ios-openid4vp-swift` 0.20.0 | OpenID4VP presentation |
| `eudi-lib-sdjwt-swift` 0.13.0 | SD-JWT support |
| `eudi-lib-ios-statium-swift` 0.3.1 | Status management |
| `swift-log` / `swift-log-file` | Logging |
| `SwiftCopyableMacro` | Copyable type macro |

All EUDI dependencies use exact version pins.

## Code Style

- Indentation: **tabs** (width 4) — enforced via `.editorconfig`
- Line endings: CRLF
- Max line length: 500
- Trim trailing whitespace: yes
- No final newline
- No SwiftLint or SwiftFormat config — follow existing patterns

## Key Patterns

- `async/await` throughout — no completion handlers
- `ObservableObject` + `@Published` for SwiftUI reactivity (`EudiWallet`, `StorageManager`)
- `actor` isolation for thread safety (`OpenId4VciService`)
- `@unchecked Sendable` for Swift 6 concurrency compliance
- Protocol-based abstractions: `PresentationService`, `DataStorageService`, `SecureArea`, `NetworkingProtocol`
- Swift Testing framework (not XCTest) for tests

## Things to Watch Out For

- Dependency versions are pinned with `exact:` — don't change without checking compatibility across the EUDI ecosystem
- `InternalssuanceModels.swift` filename has a typo ("Internalssuance") — this is the existing name, don't rename without coordinating
- The library uses Secure Enclave APIs — some functionality won't work in simulators
- Swift 6 strict concurrency is enabled — all new code must be `Sendable`-correct
