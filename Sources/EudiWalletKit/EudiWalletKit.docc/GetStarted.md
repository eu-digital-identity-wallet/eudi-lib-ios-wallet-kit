#  Get started

How to install and initialize EUDI Wallet Kit in your project

## Package installation

To use EUDI Wallet Kit, add the following dependency to your Package.swift:
```swift
dependencies: [
		.package(url: "https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit.git", .upToNextMajor(from: "0.6.6"))
]
```

Then add the Eudi Wallet package to your target's dependencies:
```swift
dependencies: [
		.product(name: "EudiWalletKit", package: "eudi-lib-ios-wallet-kit"),
]
```

## Initialization
The ``EudiWallet`` class provides a unified API for the two user attestation presentation flows. It is initialized with a document storage manager instance. For SwiftUI apps, the wallet instance can be added as an ``environmentObject`` to be accessible from all views. A KeyChain implementation of document storage is available.

```swift
let config = EudiWalletConfiguration(serviceName: "my_wallet_app", logFileName: "temp.txt")
let trustConfig = TrustConfiguration(trustSource: .etsi(.eudiRef), fallbackTrustSource: nil)
let wallet = try! EudiWallet(eudiWalletConfig: config, trustConfig: trustConfig)
wallet.openID4VpConfig = OpenId4VpConfiguration(clientIdSchemes: [.x509SanDns, .x509Hash])
wallet.transactionLogger = MyFileTransactionLogger(wallet: wallet)
wallet.loadAllDocuments()
```

### Transaction logging

Implement `TransactionLogger.log(transaction:)` with `TransactionEntry`. Persist entries by
`transactionIdentifier`: subsequent calls update the same transaction. A request is saved with
`transactionResult == .notCompleted` before credential selection, and updated after successful
response delivery. Cancellation, failures, and interrupted sessions remain `NotCompleted`.
`reasonOfNoncompletion` records a known reason.

Presentation `listOfClaimsRequested` includes the union of every DCQL credential/claim alternative,
including unavailable credential types and all `vct_values`. When claims are omitted, known paths
from all matching wallet credentials are included. `listOfClaimsPresented` contains the disclosed
claim paths. Entries do not store claim values.

### BLE Transfer Mode

The ``EudiWallet/bleTransferMode`` property controls the Bluetooth Low Energy role used during proximity (ISO 18013-5) presentation.
You can set it during initialization via ``EudiWalletConfiguration/bleTransferMode`` or update it later on the wallet instance:

- **`.server`** (default): The holder device acts as a GATT peripheral (server), advertising and waiting for the reader to connect.
- **`.client`**: The holder device acts as a GATT central (client), scanning and connecting to the reader's peripheral.
- **`.both`**: The holder device supports both modes simultaneously and advertises both in the QR device engagement.

```swift
let config = EudiWalletConfiguration(
    serviceName: "my_wallet_app",
    bleTransferMode: .server  // default; use .client or .both as needed
)
let trustConfig = TrustConfiguration(trustSource: .etsi(.eudiRef), fallbackTrustSource: nil)
let wallet = try! EudiWallet(eudiWalletConfig: config, trustConfig: trustConfig)
wallet.bleTransferMode = .client
```

### BLE Transport Factory

The ``EudiWallet/bleTransportFactory`` property lets you plug in a custom BLE transport implementation for proximity presentation. This enables alternative BLE communication channels (e.g., L2CAP or a custom BLE client mdoc transport) without modifying the library.

A transport factory conforms to the `BleTransportFactory` protocol and provides `createServer()` and `createClient()` methods that each return an `MdocBleTransport` instance. When `nil` (the default), `DefaultBleTransportFactory` is used, which creates the standard GATT server/central transports.

```swift
// Provide a custom factory at initialization
let config = EudiWalletConfiguration(
    serviceName: "my_wallet_app",
    bleTransferMode: .server,
    bleTransportFactory: MyCustomTransportFactory()
)
let trustConfig = TrustConfiguration(trustSource: .etsi(.eudiRef), fallbackTrustSource: nil)
let wallet = try! EudiWallet(eudiWalletConfig: config, trustConfig: trustConfig)
```

### OpenID4VCI Configuration

The wallet now supports multiple OpenID4VCI issuer configurations for enhanced flexibility. You can configure the wallet with a dictionary of issuer configurations:

```swift
// Configure multiple OpenID4VCI issuers with DPoP support
let issuerConfigurations: [String: OpenId4VciConfiguration] = [
    "eudi_pid_issuer": OpenId4VciConfiguration(
        credentialIssuerURL: "https://pid.issuer.example.com",
        keyAttestationsConfig: KeyAttestationConfiguration(walletAttestationsProvider: myWalletAttestationsProvider),
        requireDpop: true,
        issuerMetadataPolicy: .requireSigned(issuerTrust: issuerTrustAnchor),
        dpopKeyOptions: KeyOptions(
            secureAreaName: "SecureEnclave", curve: .P256, accessControl: .requireUserPresence
        )
    ),
    "mdl_issuer": OpenId4VciConfiguration(
        credentialIssuerURL: "https://mdl.issuer.example.com",
        keyAttestationsConfig: KeyAttestationConfiguration(walletAttestationsProvider: myWalletAttestationsProvider),
        requireDpop: false,
        issuerMetadataPolicy: .ignoreSigned
    )
]

// Register additional issuers after initialization
try wallet.registerOpenId4VciServices(issuerConfigurations)
```

Use `issuerMetadataPolicy` to control signed metadata handling per issuer:
- `.requireSigned` for issuers that require signed metadata validation
- `.ignoreSigned` for environments that still use unsigned metadata
