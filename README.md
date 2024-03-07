# EUDI Wallet Kit library for iOS

:heavy_exclamation_mark: **Important!** Before you proceed, please read
the [EUDI Wallet Reference Implementation project description](https://github.com/eu-digital-identity-wallet/.github/blob/main/profile/reference-implementation.md)

----

# EUDI ISO iOS Wallet Kit library
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![Swift](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/actions/workflows/swift.yml/badge.svg)](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/actions/workflows/swift.yml)
[![Lines of Code](https://sonarcloud.io/api/project_badges/measure?project=eu-digital-identity-wallet_eudi-lib-ios-wallet-kit&metric=ncloc&token=ceca670d1f503fb68c5545e9d6bf44465a5883a6)](https://sonarcloud.io/summary/new_code?id=eu-digital-identity-wallet_eudi-lib-ios-wallet-kit)
[![Duplicated Lines (%)](https://sonarcloud.io/api/project_badges/measure?project=eu-digital-identity-wallet_eudi-lib-ios-wallet-kit&metric=duplicated_lines_density&token=ceca670d1f503fb68c5545e9d6bf44465a5883a6)](https://sonarcloud.io/summary/new_code?id=eu-digital-identity-wallet_eudi-lib-ios-wallet-kit)
[![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=eu-digital-identity-wallet_eudi-lib-ios-wallet-kit&metric=reliability_rating&token=ceca670d1f503fb68c5545e9d6bf44465a5883a6)](https://sonarcloud.io/summary/new_code?id=eu-digital-identity-wallet_eudi-lib-ios-wallet-kit)
[![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=eu-digital-identity-wallet_eudi-lib-ios-wallet-kit&metric=vulnerabilities&token=ceca670d1f503fb68c5545e9d6bf44465a5883a6)](https://sonarcloud.io/summary/new_code?id=eu-digital-identity-wallet_eudi-lib-ios-wallet-kit)

## Overview

This repository contains the EUDI Wallet Kit library for iOS. The library is a part
of the EUDI Wallet Reference Implementation project.

This library acts as a coordinator by orchestrating the various components that are
required to implement the EUDI Wallet functionality. On top of that, it provides a simplified API
that can be used by the application to implement the EUDI Wallet functionality.

```mermaid
graph TD;
    A[eudi-lib-ios-wallet-kit]
    B[eudi-lib-ios-wallet-storage] -->  |Wallet Storage|A 
    C[eudi-lib-ios-iso18013-data-transfer] --> |Transfer Manager|A 
    D[eudi-lib-ios-openid4vci-swift] --> |OpenId4Vci Manager|A 
    E[eudi-lib-ios-siop-openid4vp-swift] --> |OpenId4Vp Manager|A 
    F[eudi-lib-ios-iso18013-security] --> |Mdoc Security|C 
    G[eudi-lib-ios-iso18013-data-model] --> |Mdoc Data Model|C 
    H[eudi-lib-ios-presentation-exchange-swift] --> E 
```

The library provides the following functionality:

- Document management
    - [x] Storage encryption
    - [x] Using iOS Secure Enclave for generating/storing documents' keypair
    - [x] Enforcing device user authentication when retrieving documents' private keys
- Document issuance
    - [x] Support for OpenId4VCI document issuance
        - [x] Authorization Code Flow
        - [ ] Pre-authorization Code Flow
        - [x] Support for mso_mdoc format
        - [ ] Support for sd-jwt-vc format
- Proximity document presentation
    - [x] Support for ISO-18013-5 device retrieval
        - [x] QR device engagement
        - [x] BLE data transfer
- Remote document presentation
    - [x] OpenId4VP document transfer
        - [x] For pre-registered verifiers
        - [x] Dynamic registration of verifiers

The library is written in Swift and is compatible with iOS 14 or higher. It is distributed as a Swift package
and can be included in any iOS project.

It is based on the following specifications:
- ISO/IEC 18013-5 – Published
- Presentation Exchange v2.0.0 - Published
- OpenID4VP – Draft 18
- SIOPv2 – Draft

## Installation
To use EUDI Wallet Kit, add the following dependency to your Package.swift:
```swift
dependencies: [
    .package(url: "https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit.git", .upToNextMajor(from: "0.2.0"))
]
```

Then add the Eudi Wallet package to your target's dependencies:
```swift
dependencies: [
    .product(name: "EudiWalletKit", package: "eudi-lib-ios-wallet-kit"),
]
```

## Initialization
The [EudiWallet](Documentation/Reference/classes/EudiWallet.md) class provides a unified API for the two user attestation presentation flows. It is initialized with a document storage manager instance. For SwiftUI apps, the wallet instance can be added as an ``environmentObject`` to be accessible from all views. A KeyChain implementation of document storage is available.

```swift
let wallet = EudiWallet.standard
wallet.userAuthenticationRequired = true
wallet.trustedReaderCertificates = [...] // array of der certificate data
wallet.openId4VpVerifierApiUri = "https:// ... verifier api uri ..."
wallet.loadDocuments()
```	

## Storage Manager
The read-only property ``storage`` is an instance of a [StorageManager](Documentation/Reference/classes/StorageManager.md) 
Currently the keychain implementation is used. It provides document management functionality using the iOS KeyChain.

The storage model provides the following models for the supported well-known document types:

|DocType|Model|
|-------|-----|
|eu.europa.ec.eudiw.pid.1|[EuPidModel](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-iso18013-data-model/blob/main/Documentation/Reference/structs/EuPidModel.md)|
|org.iso.18013.5.1.mDL|[IsoMdlModel](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-iso18013-data-model/blob/main/Documentation/Reference/structs/IsoMdlModel.md)|

For other document types the [GenericMdocModel](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-iso18013-data-model/blob/main/Documentation/Reference/structs/GenericMdocModel.md) is provided.

## Presentation Service
The [presentation service protocol](Documentation/Reference/protocols/PresentationService.md) abstracts the presentation flow. The [BlePresentationService](Documentation/Reference/classes/BlePresentationService.md) and [OpenId4VpService](Documentation/Reference/classes/OpenId4VpService.md) classes implement the proximity and remote presentation flows respectively. The [PresentationSession](Documentation/Reference/classes/PresentationSession.md) class is used to wrap the presentation service and provide @Published properties for SwiftUI screens. The following example code demonstrates the initialization of a SwiftUI view with a new presentation session of a selected [flow type](Documentation/Reference/enums/FlowType.md).

```swift
let session = eudiWallet.beginPresentation(flow: flow)
// pass the session to a SwiftUI view
ShareView(presentationSession: session)
```

On view appearance the attestations are presented with the receiveRequest method. For the BLE (proximity) case the deviceEngagement property is populated with the QR code to be displayed on the holder device.

```swift
.task {
	 if presentationSession.flow.isProximity { await presentationSession.startQrEngagement() }
	 _ = await presentationSession.receiveRequest()
}
```
After the request is received the ``presentationSession.disclosedDocuments`` contains the requested attested items. The selected state of the items can be modified via UI binding. Finally, the response is sent with the following code: 

```swift
// Send the disclosed document items after biometric authentication (FaceID or TouchID)
// if the user cancels biometric authentication, onCancel method is called
 await presentationSession.sendResponse(userAccepted: true,
  itemsToSend: presentationSession.disclosedDocuments.items, onCancel: { dismiss() }, onSuccess: {
			if let url = $0 { presentSafariView(url) }
		})
```

## Issue document using OpenID4VCI

The library provides the functionality to issue documents using OpenID4VCI. To issue a document
using this functionality, EudiWallet must be property initialized. 
To issue a document using OpenID4VCI, you need to know the document's docType.
If ``userAuthenticationRequired`` is true, user authentication is required. The authentication prompt message has localisation key "issue_document".
```swift
wallet.openID4VciIssuerUrl = "https://eudi.netcompany-intrasoft.com/pid-issuer" 
wallet.openID4VciClientId = "wallet-dev"
wallet.openID4VciRedirectUri = "eudi-openid4ci://authorize/" 
do {
  let doc = try await userWallet.issueDocument(docType: EuPidModel.euPidDocType, format: .cbor)
  // document has been added to wallet storage, you can display it
}
catch {
  // display error
}

```


## Reference
Detailed documentation is provided [here](Documentation/Reference/README.md) 

### Dependencies

The detailed functionality of the wallet kit is implemented in the following Swift Packages: [MdocDataModel18013](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-iso18013-data-model.git), [MdocSecurity18013](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-iso18013-security.git),  [MdocDataTransfer18013](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-iso18013-data-transfer.git) and
  [SiopOpenID4VP](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-siop-openid4vp-swift.git)
  [OpenID4VCI](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-openid4vci-swift)

### Sample application  
A sample application that demonstrates the usage of this library is [App Wallet UI](https://github.com/eu-digital-identity-wallet/eudi-app-ios-wallet-ui).

### Disclaimer
The released software is a initial development release version: 
-  The initial development release is an early endeavor reflecting the efforts of a short timeboxed period, and by no means can be considered as the final product.  
-  The initial development release may be changed substantially over time, might introduce new features but also may change or remove existing ones, potentially breaking compatibility with your existing code.
-  The initial development release is limited in functional scope.
-  The initial development release may contain errors or design flaws and other problems that could cause system or other failures and data loss.
-  The initial development release has reduced security, privacy, availability, and reliability standards relative to future releases. This could make the software slower, less reliable, or more vulnerable to attacks than mature software.
-  The initial development release is not yet comprehensively documented. 
-  Users of the software must perform sufficient engineering and additional testing in order to properly evaluate their application and determine whether any of the open-sourced components is suitable for use in that application.
-  We strongly recommend to not put this version of the software into production use.
-  Only the latest version of the software will be supported

### License details

Copyright (c) 2023 European Commission

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
