// swift-tools-version: 6.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
	name: "EudiWalletKit",
	platforms: [.macOS(.v14), .iOS(.v16), .watchOS(.v10)],
	products: [
		// Products define the executables and libraries a package produces, making them visible to other packages.
		.library(
			name: "EudiWalletKit",
			targets: ["EudiWalletKit"])
	],
	dependencies: [
		.package(url: "https://github.com/apple/swift-log.git", from: "1.6.3"),
		.package(url: "https://github.com/crspybits/swift-log-file", from: "0.1.0"),
		.package(url: "https://github.com/eu-digital-identity-wallet/eudi-lib-ios-iso18013-data-transfer.git", exact: "0.8.3"),
		.package(url: "https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-storage.git", exact: "0.8.0"),
		.package(url: "https://github.com/eu-digital-identity-wallet/eudi-lib-sdjwt-swift.git", exact: "0.9.2"),
		.package(url: "https://github.com/eu-digital-identity-wallet/eudi-lib-ios-siop-openid4vp-swift.git", exact: "0.17.7"),
		.package(url: "https://github.com/eu-digital-identity-wallet/eudi-lib-ios-openid4vci-swift.git",exact: "0.16.2"),
		.package(url: "https://github.com/eu-digital-identity-wallet/eudi-lib-ios-statium-swift.git", exact: "0.2.0"),
		.package(url: "https://github.com/eu-digital-identity-wallet/SwiftCopyableMacro.git", from: "0.0.3")
	],
	targets: [
		// Targets are the basic building blocks of a package, defining a module or a test suite.
		// Targets can depend on other targets in this package and products from dependencies.
		.target(
			name: "EudiWalletKit",
			dependencies: [
				.product(name: "MdocDataTransfer18013", package: "eudi-lib-ios-iso18013-data-transfer"),
				.product(name: "WalletStorage", package: "eudi-lib-ios-wallet-storage"),
				.product(name: "SiopOpenID4VP", package: "eudi-lib-ios-siop-openid4vp-swift"),
				.product(name: "OpenID4VCI", package: "eudi-lib-ios-openid4vci-swift"),
				.product(name: "eudi-lib-sdjwt-swift", package: "eudi-lib-sdjwt-swift"),
				.product(name: "Logging", package: "swift-log"),
				.product(name: "FileLogging", package: "swift-log-file"),
				.product(name: "StatiumSwift", package: "eudi-lib-ios-statium-swift"),
				.product(name: "Copyable", package: "SwiftCopyableMacro"),
			]
		),
		.testTarget(
			name: "EudiWalletKitTests",
			dependencies: ["EudiWalletKit"],
			resources: [.process("Resources")]
		),
	]
)
