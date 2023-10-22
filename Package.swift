// swift-tools-version: 5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "EudiWalletKit",
    platforms: [.macOS(.v12), .iOS("13.1")],
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "EudiWalletKit",
            targets: ["EudiWalletKit"]),
    ],
    dependencies: [
		.package(url: "https://github.com/eu-digital-identity-wallet/eudi-lib-ios-iso18013-data-transfer.git", branch: "develop"),
		.package(url: "https://github.com/apple/swift-log.git", branch: "main"),
	],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "EudiWalletKit", dependencies: [
		    	.product(name: "MdocDataTransfer18013", package: "eudi-lib-ios-iso18013-data-transfer"),
	    	    .product(name: "Logging", package: "swift-log"),
	        ]
        ),
        .testTarget(
            name: "EudiWalletKitTests",
            dependencies: ["EudiWalletKit"]),
    ]
)
