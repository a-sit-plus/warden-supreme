// swift-tools-version: 5.9
// Published from source commit: 1a11ad9b235fdfa055930b2de19f8a36770f8dad

import PackageDescription

let package = Package(
    name: "WardenSupreme",
    platforms: [.iOS(.v15)],
    products: [
        .library(name: "WardenSupreme", targets: ["WardenSupreme"])
    ],
    targets: [
        .binaryTarget(
            name: "WardenSupreme",
            url: "https://github.com/a-sit-plus/warden-supreme/releases/download/1.2.0/WardenSupreme.xcframework.zip",
            checksum: "5515ee5961aaa2999102004fc8f52fca411d7cbac6c12271bf1cb05e6210ee02"
        )
    ]
)
