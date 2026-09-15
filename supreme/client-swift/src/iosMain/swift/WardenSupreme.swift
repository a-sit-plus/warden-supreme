import Foundation
import Security

/// A set of SHA-256 certificate pins for one verifier domain.
public struct PinnedCertificate: Sendable {
    /// The verifier domain matched by the pin.
    public let domain: String

    /// Certificate fingerprints in Ktor's `sha256/<base64>` format.
    public let fingerprints: [String]

    /// Creates certificate pins for a verifier domain.
    public init(domain: String, fingerprints: [String]) {
        self.domain = domain
        self.fingerprints = fingerprints
    }
}

/// The verifier's response to a completed attestation ceremony.
public struct IosAttestationResult: Sendable {
    /// Whether the verifier accepted the attested key.
    public let successful: Bool

    /// A human-readable result or rejection message.
    public let message: String

    /// The number of certificates returned and stored for the key.
    public let certificateCount: Int
}

/// Attests Signum-backed keys with a Warden Supreme verifier.
public final class IosAttestationClient {
    private let bridge: KotlinAttestationClient

    /// Creates a client that permits cellular network access.
    public convenience init() {
        self.init(allowCellularAccess: true)
    }

    /// Creates a client with optional cellular network access.
    public convenience init(allowCellularAccess: Bool) {
        self.init(allowCellularAccess: allowCellularAccess, pins: [])
    }

    /// Creates a client with optional cellular access and certificate pinning.
    public init(allowCellularAccess: Bool = true, pins: [PinnedCertificate]) {
        bridge = KotlinAttestationClient(
            allowCellularAccess: allowCellularAccess,
            pins: pins.map {
                KotlinPinnedCertificate(
                    domain: $0.domain,
                    fingerprints: $0.fingerprints
                )
            }
        )
    }

    /// Fetches a challenge, attests the key identified by `alias`, and stores the returned certificate chain.
    ///
    /// - Parameters:
    ///   - alias: The Signum key alias to create or attest.
    ///   - challengeEndpoint: The absolute HTTP or HTTPS verifier challenge URL.
    /// - Returns: The verifier's attestation result.
    public func performAttestation(
        alias: String,
        challengeEndpoint: URL
    ) async throws -> IosAttestationResult {
        let result = try await bridge.performAttestation(
            alias: alias,
            challengeEndpoint: challengeEndpoint.absoluteString
        )
        return IosAttestationResult(
            successful: result.successful,
            message: result.message,
            certificateCount: Int(result.certificateCount)
        )
    }

    /// Returns the private Security-framework key stored by Signum for `alias`, performing user authentication if required.
    public func getAttestedKey(alias: String) async throws -> SecKey {
        let retainedKey = try await bridge.getAttestedKey(alias: alias)
        return Unmanaged<SecKey>.fromOpaque(retainedKey.pointer).takeRetainedValue()
    }

    /// Returns the leaf certificate stored for `alias`, or `nil` when no chain is stored.
    public func getAttestationKeyCertificate(alias: String) -> SecCertificate? {
        certificate(alias: alias, index: 0)
    }

    /// Returns the complete stored certificate chain, with the leaf certificate first.
    public func getAttestationCertificateChain(alias: String) -> [SecCertificate] {
        (0..<Int(bridge.getAttestationCertificateCount(alias: alias))).compactMap {
            certificate(alias: alias, index: Int32($0))
        }
    }

    private func certificate(alias: String, index: Int32) -> SecCertificate? {
        guard let pointer = bridge.getAttestationCertificate(alias: alias, index: index) else {
            return nil
        }
        return Unmanaged<SecCertificate>.fromOpaque(pointer).takeRetainedValue()
    }
}
