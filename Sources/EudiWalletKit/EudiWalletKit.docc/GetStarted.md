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
let wallet = EudiWallet.standard
wallet.userAuthenticationRequired = true
wallet.trustedReaderCertificates = [...] // array of der certificate data
wallet.openId4VpVerifierApiUri = "https:// ... verifier api uri ..."
wallet.verifierApiUri = configLogic.verifierConfig.apiUri
wallet.verifierLegalName = configLogic.verifierConfig.legalName
wallet.openID4VciIssuerUrl = configLogic.vciConfig.issuerUrl
wallet.openID4VciClientId = configLogic.vciConfig.clientId
wallet.openID4VciRedirectUri = configLogic.vciConfig.redirectUri
wallet.loadAllDocuments()
