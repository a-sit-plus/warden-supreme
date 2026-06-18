@file:OptIn(kotlin.time.ExperimentalTime::class)

package at.asitplus.attestation.supreme

import at.asitplus.attestation.FixedTimeClock
import at.asitplus.attestation.AttestationResult
import at.asitplus.attestation.android.VerifiedBootKey
import at.asitplus.signum.indispensable.AndroidKeystoreAttestation
import at.asitplus.signum.indispensable.jsonEncoded
import at.asitplus.signum.indispensable.pki.Pkcs10CertificationRequest
import at.asitplus.signum.indispensable.pki.X509Certificate as SignumX509Certificate
import at.asitplus.testballoon.matrix.matrixSuite
import examples.docs.config.grapheneos.grapheneOsConfig
import io.kotest.assertions.withClue
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate as JcaX509Certificate
import java.util.Base64
import kotlin.time.Clock
import kotlin.time.Duration.Companion.minutes

private val grapheneCertificateFactory = CertificateFactory.getInstance("X.509")

private val pixel7aGrapheneFixture = GrapheneVerifierFixture(
    attestation = AndroidKeystoreAttestation(
        listOf(
            "MIIEjDCCBDKgAwIBAgIBATAKBggqhkjOPQQDAjA5MQwwCgYDVQQKEwNURUUxKTAnBgNVBAMTIGRhMjYzYjg3NGI5YTI1YTgwNDBhN2M1NzNmOWM3ZWI5MB4XDTI2MDMyMzA5MDUyN1oXDTQ4MDEwMTAwMDAwMFowDzENMAsGA1UEAxMEdGVzdDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK7t9oeqyzeWKCfmCdvJgCfMazUsf3YiPd8a+PuFuKm9JxgNoZ3slyv7XiqKjDD00njbPbHH/2yT7vFW/gMSPZi+o5V8ArLfIpDPzIfuW1JXoEIm+0E8Za6y5CpBvbINTow3dotYAFf+4JIc7HDy/yrpM9a2ezOMNbVR6ZREM3suUJ6u8TTWSmRgK8ePnG5yet05TY9sHxGcHl7TJ6urJ5xBM3L0VoVT31iCAqP24LqSvw4ci3fKGHPYJ3NHJY73snG19R+QzXRlYd1TaDvXoajbrFfjNHy8jf58P1JeJ7zzj4KqSrCYP8HpBd9jA7V6OXQyLxbm3/TYoFklNpiFKS5WgwWk34jfFLyr+KOnZlQrFHTpkLN7WGJY8oeJCTsXx0a5gCfck6kc0+B3mCiPrEEVRF8vhkN15rp67E+mbRT/xWGztIo3to6D0zRzSEpcPKDqWr+F/7mTV0uuEoPduMIhykglH6ZHYNBieR/JijnHV81Z24/Fm0Gibo5HJJ0Howym918hNF+52DbGekifF888xK64kf9gLScXMkMSqZJFLXdKIqeY/21C/4uwgRi6zehCTPQwhxMrnDqK+9uJrCI7chTHRaz8MlqOU4TcWIkKMzR84v79VJ2/XmHf+XGPRV6Pk+BX+P1m0tCVEZHRGRd3EIcCSZbwcS0Y+hy4PAFhAgMBAAGjggGIMIIBhDAOBgNVHQ8BAf8EBAMCB4AwggFwBgorBgEEAdZ5AgERBIIBYDCCAVwCAgGQCgEBAgIBkAoBAQQgerlGxbI+3t23T2O9V7+Pvfmz3I2TRMMTIBrLxDI3M+4EADB6v4U9CAIGAZ0Z8SYBv4VFRARCMEAxGjAYBBNhdC5hc2l0cGx1cy5hdHR0ZXN0AgEBMSIEIDS5dixNbJDUhDGUDFe95zFCWLJkIO/hasf3J08NMwrVv4VUIgQgE2oMqVLLOj9SFscJGTYf+HjZ/Ew5CwfRNhvZGnGnX+0wgauhCDEGAgECAgEDogMCAQGjBAICEAClCDEGAgECAgEEv4FIBQIDAQABv4N3AgUAv4U+AwIBAL+FQEwwSgQgUI113qEMXLw+djImD8C1n2BVqKSd2E5pO22Ime27AeQBAf8KAQEEICz5sA02pfijoUdA08Bn8XaUnqzjKVH9po5Y06MTuMztv4VBBQIDAnEAv4VCBQIDAxdrv4VOBgIEATUl0b+FTwYCBAE1JdEwCgYIKoZIzj0EAwIDSAAwRQIhAIqu4Fkqq1hp0O3WC0FvNYGG/bPdBWHHtMUo/O9uP4CvAiB5+kNOk8+EcdJwMhaq6OuYzO5ISXJ5bbln5AaY1QeMeA==",
            "MIIB3zCCAYagAwIBAgIRANomO4dLmiWoBAp8Vz+cfrkwCgYIKoZIzj0EAwIwKTETMBEGA1UEChMKR29vZ2xlIExMQzESMBAGA1UEAxMJRHJvaWQgQ0EzMB4XDTI2MDMxNzExMDkzMloXDTI2MDMzMTIzNTk0MFowOTEMMAoGA1UEChMDVEVFMSkwJwYDVQQDEyBkYTI2M2I4NzRiOWEyNWE4MDQwYTdjNTczZjljN2ViOTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABB6nfUS7KzkFqEgS1LsTW9EBblAvtTOe3NgOOG2HlHGKFimkXAVj6Pl7P+cWhH0WPTfC/7kT780N3djt1PVoO1mjfzB9MB0GA1UdDgQWBBROVU+6Xq82gc8TdG753nZr2Io46TAfBgNVHSMEGDAWgBSVq426138KYJORlaFPaw5SKsPu+jAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwICBDAaBgorBgEEAdZ5AgEeBAyiARggA2ZHb29nbGUwCgYIKoZIzj0EAwIDRwAwRAIgDjP52KsOzi5lXjn6ZKmak8qbWP56v2hZdR7VR4rhNygCICojiLkMF+PEB0cnTw+G+JA3J1eIUr3CAnvAuDzVcl4F",
            "MIIB1jCCAVygAwIBAgITdyRz55GUUzrWmfqlG/X4Vul87zAKBggqhkjOPQQDAzApMRMwEQYDVQQKEwpHb29nbGUgTExDMRIwEAYDVQQDEwlEcm9pZCBDQTIwHhcNMjYwMzE5MDkwOTQwWhcNMjYwNTI4MDkwOTM5WjApMRMwEQYDVQQKEwpHb29nbGUgTExDMRIwEAYDVQQDEwlEcm9pZCBDQTMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARe3RhpHmY5Xjsn2LMOdG0wLKp5U3WpBleRM1zCHCITy7/7za5VTgG6HniLzkMz6nCjN9zwZvmxHmzZ+Fgvs+4Ho2MwYTAOBgNVHQ8BAf8EBAMCAgQwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUlauNutd/CmCTkZWhT2sOUirD7vowHwYDVR0jBBgwFoAUu/g2rYmubOLlnpTw1bLX0nrkfEEwCgYIKoZIzj0EAwMDaAAwZQIwNGPKZJ66mxvgfLwVsz0oc5kSVvygIxWMMk0Pq99nPuQiIuX3UW/wJJY2zIGcc93YAjEArLKu0pCLn4VwrEsz/GxzyaSh92Nf6SEvFSsBCrmhy8HqNmLPs3p/WhfcaHYUrdSD",
            "MIIDgDCCAWigAwIBAgIKA4gmZ2BliZaGDTANBgkqhkiG9w0BAQsFADAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MB4XDTIyMDEyNjIyNDc1MloXDTM3MDEyMjIyNDc1MlowKTETMBEGA1UEChMKR29vZ2xlIExMQzESMBAGA1UEAxMJRHJvaWQgQ0EyMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEuppxbZvJgwNXXe6qQKidXqUt1ooT8M6Q+ysWIwpduM2EalST8v/Cy2JN10aqTfUSThJha/oCtG+F9TUUviOch6RahrpjVyBdhopM9MFDlCfkiCkPCPGu2ODMj7O/bKnko2YwZDAdBgNVHQ4EFgQUu/g2rYmubOLlnpTw1bLX0nrkfEEwHwYDVR0jBBgwFoAUNmHhAHyIBQlRi0RsR/8aTMnqTxIwEgYDVR0TAQH/BAgwBgEB/wIBAjAOBgNVHQ8BAf8EBAMCAQYwDQYJKoZIhvcNAQELBQADggIBAIFxUiFHYfObqrJM0eeXI+kZFT57wBplhq+TEjd+78nIWbKvKGUFlvt7IuXHzZ7YJdtSDs7lFtCsxXdrWEmLckxRDCRcth3Eb1leFespS35NAOd0Hekg8vy2G31OWAe567l6NdLjqytukcF4KAzHIRxoFivN+tlkEJmg7EQw9D2wPq4KpBtug4oJE53R9bLCT5wSVj63hlzEY3hC0NoSAtp0kdthow86UFVzLqxEjR2B1MPCMlyIfoGyBgkyAWhd2gWN6pVeQ8RZoO5gfPmQuCsn8m9kv/dclFMWLaOawgS4kyAn9iRi2yYjEAI0VVi7u3XDgBVnowtYAn4gma5q4BdXgbWbUTaMVVVZsepXKUpDpKzEfss6Iw0zx2Gql75zRDsgyuDyNUDzutvDMw8mgJmFkWjlkqkVM2diDZydzmgi8br2sJTLdG4lUwvedIaLgjnIDEG1J8/5xcPVQJFgRf3m5XEZB4hjG3We/49p+JRVQSpE1+QzG0raYpdNsxBUO+41diQo7qC7S8w2J+TMeGdpKGjCIzKjUDAy2+gOmZdZacanFN/03SydbKVHV0b/NYRWMa4VaZbomKON38IH2ep8pdj++nmSIXeWpQE8LnMEdnUFjvDzp0f0ELSXVW2+5xbl+fcqWgmOupmU4+bxNJLtknLo49Bg5w9jNn7T7rkF",
            "MIIFHDCCAwSgAwIBAgIJANUP8luj8tazMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNVBAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcNMTkxMTIyMjAzNzU4WhcNMzQxMTE4MjAzNzU4WjAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdSSxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggjnar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGqC4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQoVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+OJtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/EgsTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRiigHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+MRPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9EaDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5UmAGMCAwEAAaNjMGEwHQYDVR0OBBYEFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMB8GA1UdIwQYMBaAFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgIEMA0GCSqGSIb3DQEBCwUAA4ICAQBOMaBc8oumXb2voc7XCWnuXKhBBK3e2KMGz39t7lA3XXRe2ZLLAkLM5y3J7tURkf5a1SutfdOyXAmeE6SRo83Uh6WszodmMkxK5GM4JGrnt4pBisu5igXEydaW7qq2CdC6DOGjG+mEkN8/TA6p3cnoL/sPyz6evdjLlSeJ8rFBH6xWyIZCbrcpYEJzXaUOEaxxXxgYz5/cTiVKN2M1G2okQBUIYSY6bjEL4aUN5cfo7ogP3UvliEo3Eo0YgwuzR2v0KR6C1cZqZJSTnghIC/vAD32KdNQ+c3N+vl2OTsUVMC1GiWkngNx1OO1+kXW+YTnnTUOtOIswUP/Vqd5SYgAImMAfY8U9/iIgkQj6T2W6FsScy94IN9fFhE1UtzmLoBIuUFsVXJMTz+Jucth+IqoWFua9v1R93/k98p41pjtFX+H8DslVgfP097vju4KDlqN64xV1grw3ZLl4CiOe/A91oeLm2UHOq6wn3esB4r2EIQKb6jTVGu5sYCcdWpXr0AUVqcABPdgL+H7qJguBw09ojm6xNIrw2OocrDKsudk/okr/AwqEyPKw9WnMlQgLIKw1rODG2NvU9oR3GVGdMkUBZutL8VuFkERQGt6vQ2OCw0sV47VMkuYbacK/xyZFiRcrPJPb41zgbQj9XAEyLKCHex0SdDrx+tWUDqG8At2JHA=="
        ).map {
            grapheneCertificateFactory.generateCertificate(Base64.getDecoder().decode(it).inputStream()) as JcaX509Certificate
        }.map { SignumX509Certificate.decodeFromDer(it.encoded) }
    ),
    challenge = Base64.getDecoder().decode("erlGxbI+3t23T2O9V7+Pvfmz3I2TRMMTIBrLxDI3M+4="),
    verificationTimeMillis = 1774256732076L
)

val GrapheneOsVerifierTest by matrixSuite {
    "android-only GrapheneOS config accepts pinned GrapheneOS attestation" {
        val verifier = grapheneOsVerifier(grapheneOsConfig)
        val keyAttestation = verifier.makoto.verifyKeyAttestation(
            pixel7aGrapheneFixture.attestation,
            pixel7aGrapheneFixture.challenge
        )

        withClue(keyAttestation.details.toString()) {
            keyAttestation.isSuccess shouldBe true
            keyAttestation.details.shouldBeInstanceOf<AttestationResult.Android.Verified>()
        }

        verifier.challengeValidator.validate(graphCsr(verifier))
            .shouldBeInstanceOf<ChallengeValidationResult.Success>()
    }

    "android-only OEM-only config rejects GrapheneOS attestation" {
        val verifier = grapheneOsVerifier(
            grapheneOsConfig.copy(
                android = grapheneOsConfig.android!!.copy(
                    verifiedBootKeys = linkedSetOf(VerifiedBootKey.OEM)
                )
            )
        )
        val keyAttestation = verifier.makoto.verifyKeyAttestation(
            pixel7aGrapheneFixture.attestation,
            pixel7aGrapheneFixture.challenge
        )

        keyAttestation.isSuccess shouldBe false
    }
}

private data class GrapheneVerifierFixture(
    val attestation: AndroidKeystoreAttestation,
    val challenge: ByteArray,
    val verificationTimeMillis: Long,
) {
    val attestationJson = attestation.jsonEncoded
}

private fun grapheneOsVerifier(config: SupremeConfiguration): AttestationVerifier {
    val timedConfig = config.copy(
        clock = object : SupremeConfiguration.Clock {
            override val timeSource: Clock
                get() = FixedTimeClock(pixel7aGrapheneFixture.verificationTimeMillis)
        },
        verificationTimeOffset = 1.minutes
    )
    return AttestationVerifier(
        timedConfig,
        nonceGenerator = suspend { pixel7aGrapheneFixture.challenge },
        challengeValidator = { _, _ -> FixedChallengeValidator() }
    )
}

private suspend fun graphCsr(verifier: AttestationVerifier) =
    createCsr(
        verifier.issueChallenge(attestationEndpoint),
        pixel7aGrapheneFixture.attestationJson,
        generateRsaKeyPair(2048)
    )

private class FixedChallengeValidator : ChallengeValidator {
    private var storedChallenge: AttestationChallenge? = null

    override suspend fun store(challenge: AttestationChallenge) {
        storedChallenge = challenge
    }

    override suspend fun validate(csr: Pkcs10CertificationRequest): ChallengeValidationResult {
        val nonce = csr.tbsCsr.nonce.getOrElse {
            return ChallengeValidationResult.Failure.NonceExtraction(it)
        }
        val challenge = storedChallenge.shouldNotBeNull()
        return if (nonce.contentEquals(challenge.nonce)) {
            ChallengeValidationResult.Success(challenge)
        } else {
            ChallengeValidationResult.Failure.Other(IllegalStateException("Nonce mismatch"))
        }
    }
}
