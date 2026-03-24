package at.asitplus.attestation.android

import at.asitplus.attestation.android.exceptions.AttestationValueException
import at.asitplus.attestation.data.AttestationData
import at.asitplus.attestation.data.attestationCertChain
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import at.asitplus.testballoon.withData
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlin.text.HexFormat
import kotlin.time.Duration.Companion.minutes

private const val ATTEST_TEST_PKG_NAME = "at.asitplus.atttest"

private val ATTEST_TEST_DIGESTS = setOf(
    "NLl2LE1skNSEMZQMV73nMUJYsmQg7+Fqx/cnTw0zCtU=".decodeBase64ToArray()
)

private val PIXEL_7A_GRAPHENE_BOOT_KEY =
    VerifiedBootKey.Digest("508d75dea10c5cbc3e7632260fc0b59f6055a8a49dd84e693b6d8899edbb01e4".hexToByteArray())

private val PIXEL_9_GRAPHENE_BOOT_KEY =
    VerifiedBootKey.Digest("9e6a8f3e0d761a780179f93acd5721ba1ab7c8c537c7761073c0a754b0e932de".hexToByteArray())

private data class GrapheneFixture(
    val data: AttestationData,
    val matchingKey: VerifiedBootKey.Digest,
    val swappedKey: VerifiedBootKey.Digest,
)

private val GRAPHENE_OS_FIXTURES = listOf(
    GrapheneFixture(
        data = AttestationData(
            name = "Google Pixel 7a GrapheneOS",
            challengeB64 = "erlGxbI+3t23T2O9V7+Pvfmz3I2TRMMTIBrLxDI3M+4=",
            attestationProofB64 = listOf(
                "MIIEjDCCBDKgAwIBAgIBATAKBggqhkjOPQQDAjA5MQwwCgYDVQQKEwNURUUxKTAnBgNVBAMTIGRhMjYzYjg3NGI5YTI1YTgwNDBhN2M1NzNmOWM3ZWI5MB4XDTI2MDMyMzA5MDUyN1oXDTQ4MDEwMTAwMDAwMFowDzENMAsGA1UEAxMEdGVzdDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK7t9oeqyzeWKCfmCdvJgCfMazUsf3YiPd8a+PuFuKm9JxgNoZ3slyv7XiqKjDD00njbPbHH/2yT7vFW/gMSPZi+o5V8ArLfIpDPzIfuW1JXoEIm+0E8Za6y5CpBvbINTow3dotYAFf+4JIc7HDy/yrpM9a2ezOMNbVR6ZREM3suUJ6u8TTWSmRgK8ePnG5yet05TY9sHxGcHl7TJ6urJ5xBM3L0VoVT31iCAqP24LqSvw4ci3fKGHPYJ3NHJY73snG19R+QzXRlYd1TaDvXoajbrFfjNHy8jf58P1JeJ7zzj4KqSrCYP8HpBd9jA7V6OXQyLxbm3/TYoFklNpiFKS5WgwWk34jfFLyr+KOnZlQrFHTpkLN7WGJY8oeJCTsXx0a5gCfck6kc0+B3mCiPrEEVRF8vhkN15rp67E+mbRT/xWGztIo3to6D0zRzSEpcPKDqWr+F/7mTV0uuEoPduMIhykglH6ZHYNBieR/JijnHV81Z24/Fm0Gibo5HJJ0Howym918hNF+52DbGekifF888xK64kf9gLScXMkMSqZJFLXdKIqeY/21C/4uwgRi6zehCTPQwhxMrnDqK+9uJrCI7chTHRaz8MlqOU4TcWIkKMzR84v79VJ2/XmHf+XGPRV6Pk+BX+P1m0tCVEZHRGRd3EIcCSZbwcS0Y+hy4PAFhAgMBAAGjggGIMIIBhDAOBgNVHQ8BAf8EBAMCB4AwggFwBgorBgEEAdZ5AgERBIIBYDCCAVwCAgGQCgEBAgIBkAoBAQQgerlGxbI+3t23T2O9V7+Pvfmz3I2TRMMTIBrLxDI3M+4EADB6v4U9CAIGAZ0Z8SYBv4VFRARCMEAxGjAYBBNhdC5hc2l0cGx1cy5hdHR0ZXN0AgEBMSIEIDS5dixNbJDUhDGUDFe95zFCWLJkIO/hasf3J08NMwrVv4VUIgQgE2oMqVLLOj9SFscJGTYf+HjZ/Ew5CwfRNhvZGnGnX+0wgauhCDEGAgECAgEDogMCAQGjBAICEAClCDEGAgECAgEEv4FIBQIDAQABv4N3AgUAv4U+AwIBAL+FQEwwSgQgUI113qEMXLw+djImD8C1n2BVqKSd2E5pO22Ime27AeQBAf8KAQEEICz5sA02pfijoUdA08Bn8XaUnqzjKVH9po5Y06MTuMztv4VBBQIDAnEAv4VCBQIDAxdrv4VOBgIEATUl0b+FTwYCBAE1JdEwCgYIKoZIzj0EAwIDSAAwRQIhAIqu4Fkqq1hp0O3WC0FvNYGG/bPdBWHHtMUo/O9uP4CvAiB5+kNOk8+EcdJwMhaq6OuYzO5ISXJ5bbln5AaY1QeMeA==",
                "MIIB3zCCAYagAwIBAgIRANomO4dLmiWoBAp8Vz+cfrkwCgYIKoZIzj0EAwIwKTETMBEGA1UEChMKR29vZ2xlIExMQzESMBAGA1UEAxMJRHJvaWQgQ0EzMB4XDTI2MDMxNzExMDkzMloXDTI2MDMzMTIzNTk0MFowOTEMMAoGA1UEChMDVEVFMSkwJwYDVQQDEyBkYTI2M2I4NzRiOWEyNWE4MDQwYTdjNTczZjljN2ViOTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABB6nfUS7KzkFqEgS1LsTW9EBblAvtTOe3NgOOG2HlHGKFimkXAVj6Pl7P+cWhH0WPTfC/7kT780N3djt1PVoO1mjfzB9MB0GA1UdDgQWBBROVU+6Xq82gc8TdG753nZr2Io46TAfBgNVHSMEGDAWgBSVq426138KYJORlaFPaw5SKsPu+jAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwICBDAaBgorBgEEAdZ5AgEeBAyiARggA2ZHb29nbGUwCgYIKoZIzj0EAwIDRwAwRAIgDjP52KsOzi5lXjn6ZKmak8qbWP56v2hZdR7VR4rhNygCICojiLkMF+PEB0cnTw+G+JA3J1eIUr3CAnvAuDzVcl4F",
                "MIIB1jCCAVygAwIBAgITdyRz55GUUzrWmfqlG/X4Vul87zAKBggqhkjOPQQDAzApMRMwEQYDVQQKEwpHb29nbGUgTExDMRIwEAYDVQQDEwlEcm9pZCBDQTIwHhcNMjYwMzE5MDkwOTQwWhcNMjYwNTI4MDkwOTM5WjApMRMwEQYDVQQKEwpHb29nbGUgTExDMRIwEAYDVQQDEwlEcm9pZCBDQTMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARe3RhpHmY5Xjsn2LMOdG0wLKp5U3WpBleRM1zCHCITy7/7za5VTgG6HniLzkMz6nCjN9zwZvmxHmzZ+Fgvs+4Ho2MwYTAOBgNVHQ8BAf8EBAMCAgQwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUlauNutd/CmCTkZWhT2sOUirD7vowHwYDVR0jBBgwFoAUu/g2rYmubOLlnpTw1bLX0nrkfEEwCgYIKoZIzj0EAwMDaAAwZQIwNGPKZJ66mxvgfLwVsz0oc5kSVvygIxWMMk0Pq99nPuQiIuX3UW/wJJY2zIGcc93YAjEArLKu0pCLn4VwrEsz/GxzyaSh92Nf6SEvFSsBCrmhy8HqNmLPs3p/WhfcaHYUrdSD",
                "MIIDgDCCAWigAwIBAgIKA4gmZ2BliZaGDTANBgkqhkiG9w0BAQsFADAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MB4XDTIyMDEyNjIyNDc1MloXDTM3MDEyMjIyNDc1MlowKTETMBEGA1UEChMKR29vZ2xlIExMQzESMBAGA1UEAxMJRHJvaWQgQ0EyMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEuppxbZvJgwNXXe6qQKidXqUt1ooT8M6Q+ysWIwpduM2EalST8v/Cy2JN10aqTfUSThJha/oCtG+F9TUUviOch6RahrpjVyBdhopM9MFDlCfkiCkPCPGu2ODMj7O/bKnko2YwZDAdBgNVHQ4EFgQUu/g2rYmubOLlnpTw1bLX0nrkfEEwHwYDVR0jBBgwFoAUNmHhAHyIBQlRi0RsR/8aTMnqTxIwEgYDVR0TAQH/BAgwBgEB/wIBAjAOBgNVHQ8BAf8EBAMCAQYwDQYJKoZIhvcNAQELBQADggIBAIFxUiFHYfObqrJM0eeXI+kZFT57wBplhq+TEjd+78nIWbKvKGUFlvt7IuXHzZ7YJdtSDs7lFtCsxXdrWEmLckxRDCRcth3Eb1leFespS35NAOd0Hekg8vy2G31OWAe567l6NdLjqytukcF4KAzHIRxoFivN+tlkEJmg7EQw9D2wPq4KpBtug4oJE53R9bLCT5wSVj63hlzEY3hC0NoSAtp0kdthow86UFVzLqxEjR2B1MPCMlyIfoGyBgkyAWhd2gWN6pVeQ8RZoO5gfPmQuCsn8m9kv/dclFMWLaOawgS4kyAn9iRi2yYjEAI0VVi7u3XDgBVnowtYAn4gma5q4BdXgbWbUTaMVVVZsepXKUpDpKzEfss6Iw0zx2Gql75zRDsgyuDyNUDzutvDMw8mgJmFkWjlkqkVM2diDZydzmgi8br2sJTLdG4lUwvedIaLgjnIDEG1J8/5xcPVQJFgRf3m5XEZB4hjG3We/49p+JRVQSpE1+QzG0raYpdNsxBUO+41diQo7qC7S8w2J+TMeGdpKGjCIzKjUDAy2+gOmZdZacanFN/03SydbKVHV0b/NYRWMa4VaZbomKON38IH2ep8pdj++nmSIXeWpQE8LnMEdnUFjvDzp0f0ELSXVW2+5xbl+fcqWgmOupmU4+bxNJLtknLo49Bg5w9jNn7T7rkF",
                "MIIFHDCCAwSgAwIBAgIJANUP8luj8tazMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNVBAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcNMTkxMTIyMjAzNzU4WhcNMzQxMTE4MjAzNzU4WjAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdSSxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggjnar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGqC4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQoVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+OJtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/EgsTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRiigHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+MRPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9EaDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5UmAGMCAwEAAaNjMGEwHQYDVR0OBBYEFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMB8GA1UdIwQYMBaAFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgIEMA0GCSqGSIb3DQEBCwUAA4ICAQBOMaBc8oumXb2voc7XCWnuXKhBBK3e2KMGz39t7lA3XXRe2ZLLAkLM5y3J7tURkf5a1SutfdOyXAmeE6SRo83Uh6WszodmMkxK5GM4JGrnt4pBisu5igXEydaW7qq2CdC6DOGjG+mEkN8/TA6p3cnoL/sPyz6evdjLlSeJ8rFBH6xWyIZCbrcpYEJzXaUOEaxxXxgYz5/cTiVKN2M1G2okQBUIYSY6bjEL4aUN5cfo7ogP3UvliEo3Eo0YgwuzR2v0KR6C1cZqZJSTnghIC/vAD32KdNQ+c3N+vl2OTsUVMC1GiWkngNx1OO1+kXW+YTnnTUOtOIswUP/Vqd5SYgAImMAfY8U9/iIgkQj6T2W6FsScy94IN9fFhE1UtzmLoBIuUFsVXJMTz+Jucth+IqoWFua9v1R93/k98p41pjtFX+H8DslVgfP097vju4KDlqN64xV1grw3ZLl4CiOe/A91oeLm2UHOq6wn3esB4r2EIQKb6jTVGu5sYCcdWpXr0AUVqcABPdgL+H7qJguBw09ojm6xNIrw2OocrDKsudk/okr/AwqEyPKw9WnMlQgLIKw1rODG2NvU9oR3GVGdMkUBZutL8VuFkERQGt6vQ2OCw0sV47VMkuYbacK/xyZFiRcrPJPb41zgbQj9XAEyLKCHex0SdDrx+tWUDqG8At2JHA=="
            ),
            isoDate = "2026-03-23T09:05:32.076604Z",
            packageOverride = ATTEST_TEST_PKG_NAME
        ),
        matchingKey = PIXEL_7A_GRAPHENE_BOOT_KEY,
        swappedKey = PIXEL_9_GRAPHENE_BOOT_KEY
    ),
    GrapheneFixture(
        data = AttestationData(
            name = "Google Pixel 9 GrapheneOS",
            challengeB64 = "mTsQcQvUcyMOfjKBc+/nL3ohQFNSLFgHVA4IN1WG10I=",
            attestationProofB64 = listOf(
                "MIIEizCCBDKgAwIBAgIBATAKBggqhkjOPQQDAjA5MQwwCgYDVQQKEwNURUUxKTAnBgNVBAMTIDE0YjYwM2FjNTg1M2MzODNiYTY3NTQxODNiNjIwYjdlMB4XDTI2MDMyMzExNTcyOFoXDTQ4MDEwMTAwMDAwMFowDzENMAsGA1UEAxMEdGVzdDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAKiR+VERRUiWmaUebyzXVrn7q7S8jcuvt1TMivVkPeinwD/XPmHB0JL8uHLudbTg5dKo5mUr//GUqyC9dlvUz4brvqK8QwKtpWpDahU5vyh1PWSxIiCzKsmHRz47wX4dTZuMY19W1HXARbM1Qv9KmwB4A49Xv+BmcTkGft7Y264JRrunSOanlmczZoW4iqKVpf8DrQAC4wvCC0MGuybDPVJQuG0w6aF9WbeSRSmR22KHu6SBep/7OytBJ3Wu1avjbD3laT96egcd6aQ0y7uJBeCyQExyk1d256QMjXEvm9GEZEHjjqLI3ey5S2Fodxl+qFobt2ufQAVxqf3gvHzK5fSfuPQq7xHClG2nZ3bJOAhpC35YukfeYXeatBCO3qoJfGwHUruKe0Da09AXUqw562Sxwewzg7lu/nFKptuTlB+aWUBxA3fEgiBxtoPNRDLj88d2/lwTVhw/5g8rx2Lu+zqlvx8tts/yO6d493MloO0jme3P8ppSk/IRXcoemocgK4N9+1iRAUkzwmWkMj+c3y9+Z+QgXG3UhWrgfxlAX822e6rdtGCeZEqbSDs+7APINicJMrsABSCnT2uFgd3mcRYrX09UglgxjVS2W5tzDtqWEGib1y9R9AA1MgmMQPeQCdm3QHNtbCBJzqhTPvY0iOaIgBTVTkGqBloWTEYL/nUPAgMBAAGjggGIMIIBhDAOBgNVHQ8BAf8EBAMCB4AwggFwBgorBgEEAdZ5AgERBIIBYDCCAVwCAgGQCgEBAgIBkAoBAQQgmTsQcQvUcyMOfjKBc+/nL3ohQFNSLFgHVA4IN1WG10IEADB6v4U9CAIGAZ0ajqMKv4VFRARCMEAxGjAYBBNhdC5hc2l0cGx1cy5hdHR0ZXN0AgEBMSIEIDS5dixNbJDUhDGUDFe95zFCWLJkIO/hasf3J08NMwrVv4VUIgQgA6Wsbji75tmN35shE+KGxfkSFybyGlBM3qej5gKkkfowgauhCDEGAgECAgEDogMCAQGjBAICEAClCDEGAgECAgEEv4FIBQIDAQABv4N3AgUAv4U+AwIBAL+FQEwwSgQgnmqPPg12GngBefk6zVchuhq3yMU3x3YQc8CnVLDpMt4BAf8KAQEEIBKh+avfEwv1Wa5yaUjhy/UkcwvbLODJz0zJ63sdorv+v4VBBQIDAnEAv4VCBQIDAxdrv4VOBgIEATUl0b+FTwYCBAE1JdEwCgYIKoZIzj0EAwIDRwAwRAIgDPcG+GbsD27c+j/8MCQtpXhItq+Pz7voLsuucgNAq6QCIGF0UvSCG+hj/eq62FAO1vWXEj+w2tSfrkOfujjUzIN6",
                "MIIB3zCCAYWgAwIBAgIQFLYDrFhTw4O6Z1QYO2ILfjAKBggqhkjOPQQDAjApMRMwEQYDVQQKEwpHb29nbGUgTExDMRIwEAYDVQQDEwlEcm9pZCBDQTMwHhcNMjYwMzIwMTAwMDQ4WhcNMjYwNDAzMDIzNzE2WjA5MQwwCgYDVQQKEwNURUUxKTAnBgNVBAMTIDE0YjYwM2FjNTg1M2MzODNiYTY3NTQxODNiNjIwYjdlMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOFyKNniT4ZVuP67zyLF7cmy7QgTahrMOk7/JqWjZ6x3AuqRyJ1rjj2NEsIbgVo9sKw7jNWuktNm+LeEhBIFiV6N/MH0wHQYDVR0OBBYEFLgFNZLp8rmfm0k8B7cbMiZmqzmMMB8GA1UdIwQYMBaAFOfPqX8xi+wH4WW5Is7SIAEG/SVaMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgIEMBoGCisGAQQB1nkCAR4EDKIBGEADZkdvb2dsZTAKBggqhkjOPQQDAgNIADBFAiBYgxenHPribbQXMu7yIVb7tb0QoNQ92L9m9YJGubUj/wIhAI9qyoN2DpRFC4XCKmd6C0atQg1FCxpV7vQgtQWq4bvZ",
                "MIIB1jCCAVygAwIBAgITbKkMhnq/1Ni3Jerp8a7rTfAEUzAKBggqhkjOPQQDAzApMRMwEQYDVQQKEwpHb29nbGUgTExDMRIwEAYDVQQDEwlEcm9pZCBDQTIwHhcNMjYwMzA3MTAwMjI5WhcNMjYwNTE2MTAwMjI4WjApMRMwEQYDVQQKEwpHb29nbGUgTExDMRIwEAYDVQQDEwlEcm9pZCBDQTMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARZOWa8u3DYtRELrVZAkktPZwIxHMUo7bHdv9u8IZAvqt7VEdojCaybaDb99iRl47bOXL0srRFInKQyeo7Fj0qeo2MwYTAOBgNVHQ8BAf8EBAMCAgQwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU58+pfzGL7AfhZbkiztIgAQb9JVowHwYDVR0jBBgwFoAUpguGpPDIfzO1YTlizT3npzpCg0gwCgYIKoZIzj0EAwMDaAAwZQIxAMoLji6pJOcDEnw2Q+NaM3jcoU3CMDjPi59OTbrh0wx/oUqby3XNXHitd+cl4g0/2wIwaREOX1X3jsYZAutVPBEaKTvhY+QmElT5rhyHgInlwQh0b0RPmFlbQYHl7E1gEwUm",
                "MIIDgDCCAWigAwIBAgIKA4gmZ2BliZaGDjANBgkqhkiG9w0BAQsFADAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MB4XDTIyMDEyNjIyNDk0NVoXDTM3MDEyMjIyNDk0NVowKTETMBEGA1UEChMKR29vZ2xlIExMQzESMBAGA1UEAxMJRHJvaWQgQ0EyMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE+9mbWCdCNnrRYaLr7VbNLAc72LMfLYTQmVdcLAz77DA0kz4o/jNcARQ9NDlJ9m31OW+ytv7djZF3Nvv1fYPvpnW+kqERpifwBvUnGOtCykgO4j0+4Gf+fqtLZxDz2SQqo2YwZDAdBgNVHQ4EFgQUpguGpPDIfzO1YTlizT3npzpCg0gwHwYDVR0jBBgwFoAUNmHhAHyIBQlRi0RsR/8aTMnqTxIwEgYDVR0TAQH/BAgwBgEB/wIBAjAOBgNVHQ8BAf8EBAMCAQYwDQYJKoZIhvcNAQELBQADggIBAK6Qdni2yhzXEukN03dze2QoFSzdKgOwm6DPhbbuGGAHB8Yfnv7JO0+1zoOUuHfWvww+5iF4BDUgTwf31agpwWkgyjSd51Lgtf/YHE/eaeJCiaNLanLFsPFoClSYTbmQje3f84hy4kUXKyrWo/eOEx87Mu7wfqUmou4E2of0Saw0CPdWw1CYJXfP6f0AG1Z2APKPprDtLESsYBdVeULgcAU36XZKrIai958AZtLKH6iP6zPiTkGr2t/iLqx735M4qIjidLhSZwRlY6WRcBsLJsisM5ft6kSpZB4IADird5UEOBoiZzgptdCa8T2tmWtCuv5MpOmMr70XBTWouXo95zCiT4Pnnhtp0k+jenjxbmnqDUJw+F5GoBhREGM3Kr7HRbJrG1BTIIRZe8xFWHbHLkoAhvd/cMVtSYCshuXHuwiONN9vMPSLjn/JlEv1t4uI0n8agiW3oMqP0ig6QyC54SVActE93zfJr/QMjtLqCQZb56ICFb9knaWFLfdr8johjMtycf2UVoyEWu4iFd1Z4yyP/6YAq10CzIp2VhFrMVcYNuZ65PLt9p2XeuwyTd5Nhbn0W7Jh2ZcvQi6ND+/ZZCBAt64ny6qiXg8h0DWgTFAugUg2eUSQrTI0mcNsS+c9F/f8wbClT5DFutYTISs1ZmDS3tQyUADUT/np67uYtaF5",
                "MIIFHDCCAwSgAwIBAgIJANUP8luj8tazMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNVBAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcNMTkxMTIyMjAzNzU4WhcNMzQxMTE4MjAzNzU4WjAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdSSxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggjnar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGqC4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQoVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+OJtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/EgsTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRiigHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+MRPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9EaDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5UmAGMCAwEAAaNjMGEwHQYDVR0OBBYEFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMB8GA1UdIwQYMBaAFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgIEMA0GCSqGSIb3DQEBCwUAA4ICAQBOMaBc8oumXb2voc7XCWnuXKhBBK3e2KMGz39t7lA3XXRe2ZLLAkLM5y3J7tURkf5a1SutfdOyXAmeE6SRo83Uh6WszodmMkxK5GM4JGrnt4pBisu5igXEydaW7qq2CdC6DOGjG+mEkN8/TA6p3cnoL/sPyz6evdjLlSeJ8rFBH6xWyIZCbrcpYEJzXaUOEaxxXxgYz5/cTiVKN2M1G2okQBUIYSY6bjEL4aUN5cfo7ogP3UvliEo3Eo0YgwuzR2v0KR6C1cZqZJSTnghIC/vAD32KdNQ+c3N+vl2OTsUVMC1GiWkngNx1OO1+kXW+YTnnTUOtOIswUP/Vqd5SYgAImMAfY8U9/iIgkQj6T2W6FsScy94IN9fFhE1UtzmLoBIuUFsVXJMTz+Jucth+IqoWFua9v1R93/k98p41pjtFX+H8DslVgfP097vju4KDlqN64xV1grw3ZLl4CiOe/A91oeLm2UHOq6wn3esB4r2EIQKb6jTVGu5sYCcdWpXr0AUVqcABPdgL+H7qJguBw09ojm6xNIrw2OocrDKsudk/okr/AwqEyPKw9WnMlQgLIKw1rODG2NvU9oR3GVGdMkUBZutL8VuFkERQGt6vQ2OCw0sV47VMkuYbacK/xyZFiRcrPJPb41zgbQj9XAEyLKCHex0SdDrx+tWUDqG8At2JHA=="
            ),
            isoDate = "2026-03-23T11:57:30.590798Z",
            packageOverride = ATTEST_TEST_PKG_NAME
        ),
        matchingKey = PIXEL_9_GRAPHENE_BOOT_KEY,
        swappedKey = PIXEL_7A_GRAPHENE_BOOT_KEY
    )
)

val GrapheneOsTests by testSuite {
    "GrapheneOS verified boot key policies" - {
        withData(nameFn = { "supreme Parser = $it" }, false, true) - { supreme ->
            withData(nameFn = { it.data.name }, GRAPHENE_OS_FIXTURES) - { fixture ->
                "single matching GrapheneOS verified boot key succeeds" {
                    assertGrapheneVerification(
                        fixture = fixture,
                        config = grapheneBaseConfig(
                            supreme = supreme,
                            verifiedBootKeys = linkedSetOf(fixture.matchingKey)
                        )
                    )
                }

                "single matching GrapheneOS verified boot key fails with OEM-only app override" {
                    assertGrapheneFailure(
                        fixture = fixture,
                        config = grapheneBaseConfig(
                            supreme = supreme,
                            verifiedBootKeys = linkedSetOf(fixture.matchingKey)
                        ).withAppVerifiedBootKeys(linkedSetOf(VerifiedBootKey.OEM))
                    )
                }

                "single matching GrapheneOS verified boot key plus OEM succeeds" {
                    assertGrapheneVerification(
                        fixture = fixture,
                        config = grapheneBaseConfig(
                            supreme = supreme,
                            verifiedBootKeys = linkedSetOf(VerifiedBootKey.OEM, fixture.matchingKey)
                        )
                    )
                }

                "single matching GrapheneOS verified boot key plus OEM fails with OEM-only app override" {
                    assertGrapheneFailure(
                        fixture = fixture,
                        config = grapheneBaseConfig(
                            supreme = supreme,
                            verifiedBootKeys = linkedSetOf(VerifiedBootKey.OEM, fixture.matchingKey)
                        ).withAppVerifiedBootKeys(linkedSetOf(VerifiedBootKey.OEM))
                    )
                }

                "both matching GrapheneOS verified boot keys plus OEM succeed for both devices" {
                    assertGrapheneVerification(
                        fixture = fixture,
                        config = grapheneBaseConfig(
                            supreme = supreme,
                            verifiedBootKeys = linkedSetOf(
                                VerifiedBootKey.OEM,
                                PIXEL_7A_GRAPHENE_BOOT_KEY,
                                PIXEL_9_GRAPHENE_BOOT_KEY
                            )
                        )
                    )
                }

                "both matching GrapheneOS verified boot keys plus OEM fail with swapped app override" {
                    assertGrapheneFailure(
                        fixture = fixture,
                        config = grapheneBaseConfig(
                            supreme = supreme,
                            verifiedBootKeys = linkedSetOf(
                                VerifiedBootKey.OEM,
                                PIXEL_7A_GRAPHENE_BOOT_KEY,
                                PIXEL_9_GRAPHENE_BOOT_KEY
                            )
                        ).withAppVerifiedBootKeys(linkedSetOf(fixture.swappedKey))
                    )
                }

                "OEM-only fails for GrapheneOS devices" {
                    assertGrapheneFailure(
                        fixture = fixture,
                        config = grapheneBaseConfig(
                            supreme = supreme,
                            verifiedBootKeys = linkedSetOf(VerifiedBootKey.OEM)
                        )
                    )
                }

                "OEM-only succeeds when app override adds the matching GrapheneOS key" {
                    assertGrapheneVerification(
                        fixture = fixture,
                        config = grapheneBaseConfig(
                            supreme = supreme,
                            verifiedBootKeys = linkedSetOf(VerifiedBootKey.OEM)
                        ).withAppVerifiedBootKeys(linkedSetOf(fixture.matchingKey))
                    )
                }

                "swapped GrapheneOS key fails" {
                    assertGrapheneFailure(
                        fixture = fixture,
                        config = grapheneBaseConfig(
                            supreme = supreme,
                            verifiedBootKeys = linkedSetOf(fixture.swappedKey)
                        )
                    )
                }

                "swapped GrapheneOS key succeeds when app override adds the matching GrapheneOS key" {
                    assertGrapheneVerification(
                        fixture = fixture,
                        config = grapheneBaseConfig(
                            supreme = supreme,
                            verifiedBootKeys = linkedSetOf(fixture.swappedKey)
                        ).withAppVerifiedBootKeys(linkedSetOf(fixture.matchingKey))
                    )
                }
            }
        }
    }
}

private fun grapheneBaseConfig(
    supreme: Boolean,
    verifiedBootKeys: Set<VerifiedBootKey>,
) = AndroidAttestationConfiguration(
    applications = listOf(
        AndroidAttestationConfiguration.AppData(
            packageName = ATTEST_TEST_PKG_NAME,
            signerFingerprints = ATTEST_TEST_DIGESTS,
            verifiedBootKeys = null
        )
    ),
    ignoreLeafValidity = true,
    attestationStatementValiditySeconds = 5.minutes.inWholeSeconds,
    verifiedBootKeys = verifiedBootKeys,
    supremeParser = supreme
)

private fun AndroidAttestationConfiguration.withAppVerifiedBootKeys(overrideKeys: Set<VerifiedBootKey>) =
    AndroidAttestationConfiguration(
        applications = applications.map {
            AndroidAttestationConfiguration.AppData(
                packageName = it.packageName,
                signerFingerprints = it.signerFingerprints,
                appVersion = it.appVersion,
                androidVersionOverride = it.androidVersionOverride,
                patchLevelOverride = it.patchLevelOverride,
                requireRemoteKeyProvisioningOverride = it.requireRemoteKeyProvisioningOverride,
                trustedRootOverrides = it.trustedRootOverrides,
                requireStrongBoxOverride = it.requireStrongBoxOverride,
                verifiedBootKeys = overrideKeys
            )
        },
        androidVersion = androidVersion,
        patchLevel = patchLevel,
        requireStrongBox = requireStrongBox,
        allowBootloaderUnlock = allowBootloaderUnlock,
        requireRollbackResistance = requireRollbackResistance,
        ignoreLeafValidity = ignoreLeafValidity,
        verificationSecondsOffset = verificationSecondsOffset,
        attestationStatementValiditySeconds = attestationStatementValiditySeconds,
        hardwareTrustedRoots = hardwareTrustedRoots,
        softwareTrustedRoots = softwareTrustedRoots,
        disableHardwareAttestation = disableHardwareAttestation,
        enableSoftwareAttestation = enableSoftwareAttestation,
        requireRemoteKeyProvisioning = requireRemoteKeyProvisioning,
        revocation = revocation,
        verifiedBootKeys = verifiedBootKeys,
        supremeParser = supremeParser
    )

private fun grapheneVerifier(config: AndroidAttestationConfiguration) = Roboto(config)

private fun String.hexToByteArray() = hexToByteArray(HexFormat.Default)

private suspend fun assertGrapheneVerification(
    fixture: GrapheneFixture,
    config: AndroidAttestationConfiguration,
) {
    grapheneVerifier(config).verify(
        fixture.data.attestationCertChain,
        fixture.data.verificationDate,
        fixture.data.challenge
    ).getOrThrow()
}

private suspend fun assertGrapheneFailure(
    fixture: GrapheneFixture,
    config: AndroidAttestationConfiguration,
) {
    shouldThrow<AttestationValueException> {
        grapheneVerifier(config).verify(
            fixture.data.attestationCertChain,
            fixture.data.verificationDate,
            fixture.data.challenge
        ).getOrThrow()
    }.reason shouldBe AttestationValueException.Reason.SYSTEM_INTEGRITY
}
