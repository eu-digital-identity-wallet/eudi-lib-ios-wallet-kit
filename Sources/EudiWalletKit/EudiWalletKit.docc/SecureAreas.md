# Custom key management

Eudi Wallet Kit supports custom key management through the implementation of SecureArea and SecureKeyStorage protocols. This document details the process of integrating custom key management with the library.

### Secure areas

The wallet developer can customize cryptographic key operations by passing [SecureArea](https://eu-digital-identity-wallet.github.io/eudi-lib-ios-iso18013-data-model/documentation/mdocdatamodel18013/securearea) instances to the wallet. In the absence of custom instances, the wallet kit automatically generates [SecureEnclaveSecureArea](https://eu-digital-identity-wallet.github.io/eudi-lib-ios-iso18013-security/documentation/mdocsecurity18013/secureenclavesecurearea) (default) and [SoftwareSecureArea](https://eu-digital-identity-wallet.github.io/eudi-lib-ios-iso18013-security/documentation/mdocsecurity18013/softwaresecurearea) secure areas. 

The secure area instance must be initialized with a secure key storage area implementing the [SecureKeyStorage](https://eu-digital-identity-wallet.github.io/eudi-lib-ios-iso18013-data-model/documentation/mdocdatamodel18013/securekeystorage) protocol. An iOS keychain-based storage is provided via the [KeyChainSecureKeyStorage](https://eu-digital-identity-wallet.github.io/eudi-lib-ios-wallet-storage/documentation/walletstorage/keychainsecurekeystorage) actor. 

Assuming that the application developer has implemented the SecureArea protocol and registered an instance with the wallet kit, it will be available for custom secure area cryptographic operations. The following example demonstrates how to register a custom secure area with the Wallet Kit:

```swift
let keyChainStorage = KeyChainSecureKeyStorage(serviceName: self.serviceName, accessGroup: nil)
let mySecureArea = MySecureArea(storage: keyChainStorage)
let wallet = try! EudiWallet(serviceName: "wallet_dev_ui",
		trustedReaderCertificates: [Data(name: "eudi_pid_issuer_ut", ext: "der")!],
		secureAreas: [mySecureArea])
```

### Secure key creation on issuing

For each document type, the wallet developer has the flexibility to define specific key creation parameters, including the [secure area name](https://eu-digital-identity-wallet.github.io/eudi-lib-ios-iso18013-data-model/documentation/mdocdatamodel18013/securearea/name-1uugf), [curve type](https://eu-digital-identity-wallet.github.io/eudi-lib-ios-iso18013-data-model/documentation/mdocdatamodel18013/coseeccurve), [key access control](https://eu-digital-identity-wallet.github.io/eudi-lib-ios-iso18013-data-model/documentation/mdocdatamodel18013/keyaccesscontrol) and [key unlock policy](https://eu-digital-identity-wallet.github.io/eudi-lib-ios-iso18013-data-model/documentation/mdocdatamodel18013/keyaccessprotection).

Specifically:

- The ``EudiWallet/issueDocument(docType:scope:identifier:keyOptions:promptMessage:)`` has been extended to support an
additional [keyOptions](https://eu-digital-identity-wallet.github.io/eudi-lib-ios-iso18013-data-model/documentation/mdocdatamodel18013/keyoptions) optional parameter to specify the secure area name and other key options for the key creation. 
- The ``EudiWallet/issueDocumentsByOfferUrl(offerUri:docTypes:docTypeKeyOptions:txCodeValue:promptMessage:claimSet:)`` has been extended to support a `docTypeKeyOptions` to specify the secure area name and other key options for each doc type.

```swift
// For keychain saved keys, the iOS will automatically present a biometric or user PIN screen to authorize key usage for PID documents
let docTypeKeyOptions: [EuPidModel.euPidDocType : KeyOptions(secureAreaName: "Software", accessControl: [.requireUserPresence])]
let issuedDocs = try await wallet.issueDocumentsByOfferUrl(offerUri: uriOffered, docTypes: docIssueOffered.docModels, docTypeKeyOptions: docTypeKeyOptions)
```
### Secure key usage on presentation

During presentation with BLE proximity or OpenID4VP, the private key is used to create a device signature. The secure area is automatically used to sign the device response. An unlock key hook is provided via the [unlockKey](https://eu-digital-identity-wallet.github.io/eudi-lib-ios-iso18013-data-model/documentation/mdocdatamodel18013/securearea/unlockkey(id:)-19q3g) method which is internally called to get the optional `unlockData`. 
