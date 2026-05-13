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
	let certificates = ["pidissuerca02_cz", "pidissuerca02_ee", "pidissuerca02_eu", "pidissuerca02_lu", "pidissuerca02_nl", "pidissuerca02_pt", "pidissuerca02_ut"]
    wallet = try! EudiWallet(serviceName: "my_wallet_app", trustedReaderCertificates: certificates.map { Data(name: $0, ext: "der")! }, logFileName: "temp.txt")
    wallet.userAuthenticationRequired = true
    wallet.openID4VpConfig = OpenId4VpConfiguration(clientIdSchemes: [.x509SanDns, .x509Hash])
    wallet.transactionLogger = MyFileTransactionLogger(wallet: wallet)
	wallet.loadAllDocuments()
```

### BLE Transfer Mode

The ``EudiWallet/bleTransferMode`` property controls the Bluetooth Low Energy role used during proximity (ISO 18013-5) presentation.
You can set it during initialization via ``EudiWalletConfiguration/bleTransferMode`` or update it later on the wallet instance:

- **`.server`** (default): The holder device acts as a GATT peripheral (server), advertising and waiting for the reader to connect.
- **`.client`**: The holder device acts as a GATT central (client), scanning and connecting to the reader's peripheral.
- **`.both`**: The holder device supports both modes simultaneously and advertises both in the QR device engagement.

```swift
let config = EudiWalletConfiguration(
    serviceName: "my_wallet_app",
    trustedReaderCertificates: [Data(name: "eudi_pid_issuer_ut", ext: "der")!],
    bleTransferMode: .server  // default; use .client or .both as needed
)
let wallet = try! EudiWallet(eudiWalletConfig: config)
wallet.bleTransferMode = .client
```

### OpenID4VCI Configuration

The wallet now supports multiple OpenID4VCI issuer configurations for enhanced flexibility. You can configure the wallet with a dictionary of issuer configurations:

```swift
// Configure multiple OpenID4VCI issuers with DPoP support
let issuerConfigurations: [String: OpenId4VciConfiguration] = [
    "eudi_pid_issuer": OpenId4VciConfiguration(
        credentialIssuerURL: "https://pid.issuer.example.com",
        requireDpop: true,
        issuerMetadataPolicy: .requireSigned,
        dpopKeyOptions: KeyOptions(
            secureAreaName: "SecureEnclave", curve: .P256, accessControl: .requireUserPresence
        )
    ),
    "mdl_issuer": OpenId4VciConfiguration(
        credentialIssuerURL: "https://mdl.issuer.example.com",
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
