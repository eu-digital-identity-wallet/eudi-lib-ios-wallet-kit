#  ``EudiWalletKit``

EUDI Wallet Kit library for iOS

## Overview


This repository contains the EUDI Wallet Kit library for iOS. The library is a part
			of the EUDI Wallet Reference Implementation project.

This library acts as a coordinator by orchestrating the various components that are
			required to implement the EUDI Wallet functionality. On top of that, it provides a simplified API
			that can be used by the application to implement the EUDI Wallet functionality.


The library depends on the following EUDI libraries:

|Library path|Library name|Documentation|
|-------|------|------|
|[iso18013-data-model](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-iso18013-data-model.git) |MdocDataModel18013| [Documentation](https://eu-digital-identity-wallet.github.io/eudi-lib-ios-iso18013-data-model/documentation/mdocdatamodel18013/) |
|[iso18013-data-transfer](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-iso18013-data-transfer.git) |MdocDataTransfer18013| [Documentation](https://eu-digital-identity-wallet.github.io/eudi-lib-ios-iso18013-data-transfer/documentation/mdocdatatransfer18013/) |
|[iso18013-security](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-iso18013-security.git) |MdocSecurity18013| [Documentation](https://eu-digital-identity-wallet.github.io/eudi-lib-ios-iso18013-security/documentation/mdocsecurity18013/) |
|[wallet-storage](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-storage.git) |WalletStorage| [Documentation](https://eu-digital-identity-wallet.github.io/eudi-lib-ios-wallet-storage/documentation/walletstorage/)  |
|[openid4vp-swift](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-siop-openid4vp-swift.git) |SiopOpenID4VP| [Documentation](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-siop-openid4vp-swift) |
|[presentation-exchange-swift](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-presentation-exchange-swift.git) |PresentationExchange| [Documentation](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-presentation-exchange-swift) |
|[openid4vci-swift](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-openid4vci-swift) |OpenID4VCI| [Documentation](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-openid4vci-swift) |


![A screenshot of the Wallet Kit architecture](WalletKitArchitecture)

## Topics

### Essentials

- <doc:GetStarted>
- <doc:ManageDocuments>
- <doc:IssueDocuments>
- <doc:SecureAreas>
- <doc:PresentationService>

@Links(visualStyle: detailedGrid) {
	- <doc:WalletUI>
}


