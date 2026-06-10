package at.asitplus.attestation

import at.asitplus.testballoon.matrix.*

val JavaSpringInteropBridgeTest by matrixSuite {
    "java can call spring config loaders through Class overloads" {
        JavaSpringInteropAssertions.run()
    }
}
