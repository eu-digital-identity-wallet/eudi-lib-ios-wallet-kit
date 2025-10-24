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

### OpenID4VCI Configuration

The wallet now supports multiple OpenID4VCI issuer configurations for enhanced flexibility. You can configure the wallet with a dictionary of issuer configurations:

```swift
// Configure multiple OpenID4VCI issuers with DPoP support
let issuerConfigurations: [String: OpenId4VciConfiguration] = [
    "eudi_pid_issuer": OpenId4VciConfiguration(
        credentialIssuerURL: "https://pid.issuer.example.com",
        useDpopIfSupported: true,
        dpopKeyOptions: KeyOptions(
            secureAreaName: "SecureEnclave", curve: .P256, accessControl: .requireUserPresence
        )
    ),
    "mdl_issuer": OpenId4VciConfiguration(
        credentialIssuerURL: "https://mdl.issuer.example.com",
        useDpopIfSupported: false
    )
]

// Register additional issuers after initialization
try wallet.registerOpenId4VciServices(issuerConfigurations)
```
