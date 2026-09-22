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

/// A primitive value type requested by the verifier for attestation.
public enum AttestedAttributeType: String, Sendable {
    case null = "NULL"
    case boolean = "BOOLEAN"
    case string = "STRING"
    case byte = "BYTE"
    case short = "SHORT"
    case int = "INT"
    case long = "LONG"
    case character = "CHAR"
    case float = "FLOAT"
    case double = "DOUBLE"
    case byteArray = "BYTEARRAY"
}

/// One ordered client-provided attribute requested by the verifier.
public struct AttestedAttributeRequest: Sendable {
    public let name: String
    public let type: AttestedAttributeType
    public let required: Bool
}

/// A client-provided primitive value to bind into the attestation ceremony.
public enum AttestedAttributeValue: Sendable {
    case null
    case boolean(Bool)
    case string(String)
    case byte(Int8)
    case short(Int16)
    case int(Int32)
    case long(Int64)
    case character(Character)
    case float(Float)
    case double(Double)
    case byteArray(Data)
}

/// Supplies values in the same order as the verifier's requests. Use `nil` for an omitted optional value.
public typealias AdditionalAttributesProvider = ([AttestedAttributeRequest]) -> [AttestedAttributeValue?]

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
        try await performAttestation(
            alias: alias,
            challengeEndpoint: challengeEndpoint,
            additionalAttributes: { requests in requests.map { _ in nil } }
        )
    }

    /// Fetches a challenge, supplies requested client attributes, attests the key, and stores its certificate chain.
    ///
    /// The provider is called once only when the verifier requests attributes. Return exactly one value per request in
    /// the same order. An omitted optional value is `nil`; required values must be present and match the requested type.
    public func performAttestation(
        alias: String,
        challengeEndpoint: URL,
        additionalAttributes: @escaping AdditionalAttributesProvider
    ) async throws -> IosAttestationResult {
        let result = try await bridge.performAttestation(
            alias: alias,
            challengeEndpoint: challengeEndpoint.absoluteString,
            additionalAttributes: { requested in
                let requests = requested.map { descriptor in
                    AttestedAttributeRequest(
                        name: descriptor.name,
                        type: AttestedAttributeType(rawValue: descriptor.type)!,
                        required: descriptor.required
                    )
                }
                return additionalAttributes(requests).map { $0?.bridgeValue ?? .missing }
            }
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

private extension AttestedAttributeValue {
    var bridgeValue: KotlinAttestedAttributeValue {
        switch self {
        case .null:
            KotlinAttestedAttributeValue(type: "NULL", booleanValue: false, stringValue: nil, integerValue: 0, floatingPointValue: 0, bytesValue: nil)
        case .boolean(let value):
            KotlinAttestedAttributeValue(type: "BOOLEAN", booleanValue: value, stringValue: nil, integerValue: 0, floatingPointValue: 0, bytesValue: nil)
        case .string(let value):
            KotlinAttestedAttributeValue(type: "STRING", booleanValue: false, stringValue: value, integerValue: 0, floatingPointValue: 0, bytesValue: nil)
        case .byte(let value):
            KotlinAttestedAttributeValue(type: "BYTE", booleanValue: false, stringValue: nil, integerValue: Int64(value), floatingPointValue: 0, bytesValue: nil)
        case .short(let value):
            KotlinAttestedAttributeValue(type: "SHORT", booleanValue: false, stringValue: nil, integerValue: Int64(value), floatingPointValue: 0, bytesValue: nil)
        case .int(let value):
            KotlinAttestedAttributeValue(type: "INT", booleanValue: false, stringValue: nil, integerValue: Int64(value), floatingPointValue: 0, bytesValue: nil)
        case .long(let value):
            KotlinAttestedAttributeValue(type: "LONG", booleanValue: false, stringValue: nil, integerValue: value, floatingPointValue: 0, bytesValue: nil)
        case .character(let value):
            KotlinAttestedAttributeValue(type: "CHAR", booleanValue: false, stringValue: String(value), integerValue: 0, floatingPointValue: 0, bytesValue: nil)
        case .float(let value):
            KotlinAttestedAttributeValue(type: "FLOAT", booleanValue: false, stringValue: nil, integerValue: 0, floatingPointValue: Double(value), bytesValue: nil)
        case .double(let value):
            KotlinAttestedAttributeValue(type: "DOUBLE", booleanValue: false, stringValue: nil, integerValue: 0, floatingPointValue: value, bytesValue: nil)
        case .byteArray(let value):
            KotlinAttestedAttributeValue(type: "BYTEARRAY", booleanValue: false, stringValue: nil, integerValue: 0, floatingPointValue: 0, bytesValue: value)
        }
    }
}

private extension KotlinAttestedAttributeValue {
    static var missing: KotlinAttestedAttributeValue {
        KotlinAttestedAttributeValue(type: "MISSING", booleanValue: false, stringValue: nil, integerValue: 0, floatingPointValue: 0, bytesValue: nil)
    }
}
