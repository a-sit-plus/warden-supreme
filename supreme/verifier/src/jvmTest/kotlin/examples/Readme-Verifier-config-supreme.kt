package examples.docs.config.minimal

import at.asitplus.attestation.supreme.AttestationVerifier
import at.asitplus.attestation.supreme.InMemoryChallengeCache
import at.asitplus.attestation.supreme.SupremeConfiguration
import at.asitplus.attestation.supreme.WardenDefaults

private val configuration: SupremeConfiguration =
    SupremeConfiguration(android = makoto.androidAttestationConfiguration!!, ios = makoto.iosAttestationConfiguration!!)






val verifierFromConfig = AttestationVerifier(
    configuration,
 /*(1)!*/WardenDefaults.nonceGenerator
) {/*(2)!*/clock, offset -> InMemoryChallengeCache(clock, offset) }