# EUDI Wallet Kit - AI Coding Agent Instructions

## Project Overview
This is an iOS/macOS library for implementing EU Digital Identity Wallet functionality. It orchestrates multiple EUDI components to provide document management, OpenID4VCI issuance, and presentation flows (BLE proximity and OpenID4VP remote).

## Architecture

### Core Components
- **EudiWallet**: Main coordinator class (`Sources/EudiWalletKit/EudiWallet.swift`) - entry point for all wallet operations
- **StorageManager**: Document persistence and model transformation (`Sources/EudiWalletKit/Services/StorageManager.swift`)
- **PresentationService**: Protocol-based abstraction for data sharing (`BlePresentationService`, `OpenId4VpService`)
- **OpenId4VCIService**: Handles credential issuance via OpenID4VCI protocol

### Key Abstractions
- **SecureArea**: Cryptographic key management abstraction with two default implementations:
  - `SecureEnclaveSecureArea`: Uses iOS Secure Enclave (hardware-backed)
  - `SoftwareSecureArea`: Software-only fallback
  - Registry pattern: `SecureAreaRegistry.shared.register(secureArea:)` in `EudiWallet.init`
  
- **Document Formats**: Dual format support (check `DocDataFormat` enum):
  - `.cbor`: ISO/IEC 18013-5 mDocs (msoMdoc)
  - `.sdjwt`: SD-JWT verifiable credentials
  - Format-specific parsing: `StorageManager.toCborMdocModel()` vs `StorageManager.toSdJwtDocModel()`

- **Credential Policies**: Controls credential lifecycle (`CredentialOptions`):
  - `.oneTimeUse`: Single presentation, then consume
  - `.rotateUse`: Unlimited presentations, rotate on use
  - Batch size determines how many credentials to issue at once

### Configuration Patterns
- **Multi-issuer support**: `openID4VciConfigurations` dictionary maps issuer names to `OpenId4VciConfiguration`
  ```swift
  let configs = [
    "pid_issuer": OpenId4VciConfiguration(credentialIssuerURL: "https://...", useDpopIfSupported: true),
    "mdl_issuer": OpenId4VciConfiguration(...)
  ]
  ```
- **DPoP support**: When `useDpopIfSupported: true`, library auto-negotiates DPoP keys using `dpopKeyOptions` (curve, secure area, auth requirements)

## Development Workflows

### Running Tests
```bash
# Via Fastlane (preferred)
fastlane tests

# Code coverage report
fastlane code_coverage  # Opens HTML report at xcov_output/index.html

# Direct SPM (CI mode adds -skipPackagePluginValidation)
swift test --package-path .
```

### Build Commands
```bash
# Resolve dependencies
swift package resolve

# Build library
swift build

# Generate documentation (DocC)
swift package generate-documentation --target EudiWalletKit
```

### Important Conventions
- **Async/await everywhere**: All public APIs are async (document operations, issuance, presentation)
- **ObservableObject pattern**: `EudiWallet` and `StorageManager` are `@ObservableObject` for SwiftUI integration
- **Error handling**: Use `WalletError` wrapper, check `PresentationSession.makeError(str:localizationKey:)` for localized errors
- **User authentication**: `userAuthenticationRequired` property gates biometric/passcode prompts via `EudiWallet.authorizedAction()`

## Critical Patterns

### Document Issuance Flow
1. **Resolve offer** (optional): `resolveOfferUrlDocTypes(offerUri:)` → `OfferedIssuanceModel`
2. **Issue document**: `issueDocument(issuerName:docTypeIdentifier:credentialOptions:keyOptions:)`
   - `DocTypeIdentifier` enum: `.msoMdoc(docType:)`, `.sdJwt(vct:)`, or `.identifier(configId)`
   - `KeyOptions` specifies secure area: `KeyOptions(secureAreaName: "SecureEnclave")`
3. **Handle deferred/pending**:
   - Check `doc.status` (.issued, .deferred, .pending)
   - Deferred: `requestDeferredIssuance(issuerName:deferredDoc:credentialOptions:keyOptions:)`
   - Pending (dynamic issuance): `resumePendingIssuance(...webUrl:...)` after OpenID4VP presentation

### Presentation Flow
1. **Begin session**: `beginPresentation(flow: .ble)` or `flow: .openid4vp(qrCode)`
2. **Receive request**: `session.receiveRequest()` → populates `session.disclosedDocuments`
3. **Send response**: `session.sendResponse(userAccepted:itemsToSend:onSuccess:onCancel:)`
   - Automatically handles biometric auth if `userAuthenticationRequired == true`

### Model Transformation
- Documents stored as raw data (CBOR or SD-JWT strings)
- Decoded to strongly-typed models: `EuPidModel`, `IsoMdlModel`, or `GenericMdocModel`
- Conversion: `StorageManager.toClaimsModel(doc:uiCulture:modelFactory:)`
- Custom models: Implement `DocClaimsDecodableFactory` protocol

### Service Registration
- OpenId4VCI services registered by name: `registerOpenId4VciService(name:config:)`
- Retrieved via: `OpenId4VCIServiceRegistry.shared.get(name:)`
- Secure areas registered at init via `SecureAreaRegistry.shared`

## Testing Specifics
- Uses Swift Testing framework (not XCTest)
- Test resources in `Tests/EudiWalletKitTests/Resources/`: DCQL samples, mDocs, SD-JWTs
- Mocking: Create custom `DataStorageService` or `NetworkingProtocol` implementations
- Example: `EudiWalletKitTests.swift` shows DCQL parsing, JWT verification, session transcript generation

## Dependencies & Integration
- **External EUDI libs** (see `Package.swift`):
  - `eudi-lib-ios-iso18013-data-transfer`: BLE proximity transfer
  - `eudi-lib-ios-wallet-storage`: KeyChain storage abstraction
  - `eudi-lib-ios-siop-openid4vp-swift`: Remote presentation
  - `eudi-lib-ios-openid4vci-swift`: Credential issuance
- **Logging**: Uses `swift-log` library. Create logger: `Logger(label: "com.example.feature")`
  - Configure file logging via `EudiWallet.logFileName` property

## Common Pitfalls
- **Service name restriction**: Cannot contain `:` character (KeyChain constraint)
- **Credential consumption**: Check `credentialsUsageCounts` before presentation to avoid "no available credentials" errors
- **Secure area availability**: `SecureEnclave.isAvailable` check required before using `"SecureEnclave"` secure area
- **Format mismatch**: BLE only supports `.cbor` format; OpenID4VP supports both
- **Metadata caching**: `cacheIssuerMetadata: true` in config avoids repeated network calls but may serve stale data

## Key File References
- Main API: `Sources/EudiWalletKit/EudiWallet.swift`
- Document models: `Sources/EudiWalletKit/Models/DocElements.swift`
- Presentation session: `Sources/EudiWalletKit/Services/PresentationSession.swift`
- OpenID4VCI config: `Sources/EudiWalletKit/Models/OpenId4VciConfiguration.swift`
- Storage abstraction: `Sources/EudiWalletKit/Services/StorageManager.swift`
