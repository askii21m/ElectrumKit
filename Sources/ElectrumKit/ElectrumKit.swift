import Foundation
import CryptoKit
import Network

#if DEBUG
import os.log
#endif

/// A single ASCII newline byte (`\n`) used to terrminate packets
///
/// - Important: This is always ASCII `0x0A`.
fileprivate let newline: UInt8 = 0x0A

/// A single ASCII space byte (`' '`) used to pad packets
///
/// - Important: This is always ASCII `0x20`.
fileprivate let space: UInt8 = 0x20

/// Errors thrown by the Electrum client
public enum ElectrumError: Error, Equatable {
    /// The network connection was closed before the request could complete
    case connectionClosed
    /// The request exceeded the configured timeout
    case requestTimeout
    /// The client has reached its configured concurrent request limit
    case requestLimit
    /// An unknown error occurred
    case unknown
}

/// Electrum client configuration
public struct ElectrumConfig {
    /// Keychain service for persisting pinned certificates and CA trust markers
    public let certPath: String
    /// Maximum number of outstanding requests the client will allow
    public let requestLimit: Int
    /// Minimum size before flushing the send buffer
    ///
    /// The client will pad RPC payloads up to the next power of
    /// two that is greater than or equal to `packetMinSize`.
    public let packetMinSize: Int
    /// Minimum amount of time to wait before flushing the send buffer
    public let packetMinWait: TimeInterval
    /// Force immediate sends, regardless of `packetMinSize` and `packetMinWait`
    public let packetForceSend: Bool
    /// Minimum TLS protocol version to allow
    ///
    /// - Important: TLS versions lower than TLS 1.2 are deprecated and should
    ///              not be used. Use `.TLSv12` or higher.
    public let tlsMinVersion: tls_protocol_version_t
   
    public init(
        certPath: String = "electrum.client.certificates",
        requestLimit: Int = 100,
        packetMinSize: Int = 1024,
        packetMinWait: TimeInterval = 1.0,
        packetForceSend: Bool = false,
        tlsMinVersion: tls_protocol_version_t = .TLSv12
    ) {
        self.certPath = certPath
        self.requestLimit = requestLimit
        self.packetMinSize = packetMinSize
        self.packetMinWait = packetMinWait
        self.packetForceSend = packetForceSend
        self.tlsMinVersion = tlsMinVersion
    }
}

/// An encodable JSON-RPC request
struct RPCRequest: Encodable {
    let method: String
    let params: [String]
    let id: Int

    init(method: String, params: [String], id: Int) {
        self.method = method
        self.params = params
        self.id = id
    }
}

/// Lightweight Electrum client.
///
/// This class manages a single `NWConnection` to an Electrum-compatible server,
/// supports simple request/response interactions and persistent subscriptions.
public final class ElectrumClient {
    #if DEBUG
    // Logger is only used in DEBUG builds
    private let logger: Logger = Logger(subsystem: "electrum", category: "client")
    #endif
    
    // Connection target
    private let host: String
    private let port: UInt16
    private let config: ElectrumConfig
    
    // Buffers and timers
    private var sendTask: DispatchWorkItem? = nil
    private var sendLast: DispatchTime = .now()
    private var sendBuffer: Data = Data()
    private var receiveBuffer: Data = Data()
    
    // Request management
    private var requestId: Int = 1
    private var requests: [Int: NetworkRequest] = [:]
    private var subscriptions: [String: NetworkSubscription] = [:]
    
    // Keychain queries for persisting pinned certificates and CA trust markers
    private let pinnedKeychainQuery: [String: Any]
    private let caKeychainQuery: [String: Any]
    
    // Network connection and state
    private var connection: NWConnection?
    private var connected: Bool = false
    private var retries: Int = 0
    
    // Internal queues
    private let main: DispatchQueue
    private let write: DispatchQueue
    private let verify: DispatchQueue
    
    // MARK: - Internal helper types
    
    private struct NetworkSubscription {
        /// Handler invoked with the received data payloads for the subscription
        let handler: ([String]) -> Void
    }
    
    private struct NetworkRequest {
        /// Completion used to return result to the caller
        let completion: (Result<String, ElectrumError>) -> Void
        /// Optional timer that triggers request timeout handling
        let timer: DispatchSourceTimer?
    }
    
    public init(
        host: String,
        port: UInt16,
        config: ElectrumConfig = ElectrumConfig()
    ) {
        self.host = host
        self.port = port
        self.config = config
        
        main = DispatchQueue(
            label: "\(host).main",
            attributes: .concurrent
        )
        write = DispatchQueue(
            label: "\(host).write"
        )
        verify = DispatchQueue(
            label: "\(host).tls"
        )
        
        // Base queries used for saving certificates + markers to the keychain
        caKeychainQuery = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "\(config.certPath).ca",
            kSecAttrAccount as String: host
        ]
        pinnedKeychainQuery = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "\(config.certPath).pinned",
            kSecAttrAccount as String: host,
        ]
    }
    
    deinit {
        stop()
    }
    
    // MARK: - Public API
    
    /// Starts the client and initiates a connection to the server
    ///
    /// This function is safe to call from any queue; it dispatches internal work
    /// onto the client's `main` queue.
    public func start() {
        main.async(flags: .barrier) { [weak self] in
            self?.connect()
        }
    }
    
    /// Stops the client and gracefully terminates the connection
    ///
    /// Cancelling the connection will also clear outstanding requests and
    /// subscriptions
    public func stop() {
        main.async(flags: .barrier) { [weak self] in
            self?.disconnect()
        }
    }
    
    /// Sends an RPC request to the server
    ///
    /// - Parameters:
    ///   - method: Request method name
    ///   - params: Array of string parameters for the request
    ///   - timeout: Optional timeout in seconds for the request
    ///   - completion: Completion invoked with the result or an `ElectrumError`
    public func request(
        method: String,
        params: [String] = [],
        timeout: TimeInterval? = nil,
        completion: @escaping (Result<String, ElectrumError>) -> Void
    ) {
        main.async(flags: .barrier) { [weak self] in
            guard let self = self else { return }

            // Ensure connection is open
            guard self.connected else {
                self.log("Request \"\(method)\" failed: connection closed")
                completion(.failure(.connectionClosed))
                return
            }
            
            // Enforce request concurrency limit
            guard self.requests.count < config.requestLimit else {
                self.log("Request \"\(method)\" failed: request limit reached")
                completion(.failure(.requestLimit))
                return
            }
            
            let currentId = self.requestId
            self.requestId += 1
        
            var timer: DispatchSourceTimer? = nil
            if let timeout = timeout {
                // Start the countdown for the request timeout
                let source = DispatchSource.makeTimerSource(queue: self.main)
                source.schedule(deadline: .now() + timeout)
                source.setEventHandler { [weak self] in
                    self?.handleRequestTimeout(currentId)
                }
                
                source.resume()
                timer = source
            }

            // Store the request context so responses
            // and their timeouts can be correlated
            self.requests[currentId] = NetworkRequest(
                completion: completion,
                timer: timer
            )
            
            let request = RPCRequest(
                method: method,
                params: params,
                id: currentId
            )
            
            self.log("Requesting { \"\(method)\", \(params) }")
            
            // Encode JSON payload
            let data = try? JSONEncoder().encode(request)
            guard
                var data = data,
                !data.isEmpty
            else {
                self.log("Failed to encode { \"\(method)\", \(params) }")
                return
            }
            
            // Each RPC call MUST be terminated by
            // a single newline to delimit messages
            data.append(newline)
            self.enqueuePacket(data)
        }
    }
    
    /// Subscribes to server notifications for a given method and params
    ///
    /// - Parameters:
    ///   - method: Subscription method name
    ///   - params: Array of string parameters for the subscription
    ///   - handler: Handler invoked with subscription responses
    ///
    /// Subscriptions are stored locally and will be re-requested on reconnect.
    public func subscribe(
        method: String,
        params: [String] = [],
        handler: @escaping ([String]) -> Void
    ) {
        let key = self.key(
            method: method,
            params: params
        )
        
        main.async(flags: .barrier) { [weak self] in
            guard let self = self else { return }

            // Subscriptions can be keyed in without an active connection
            // All subscriptions will be re-established on reconnect
            self.subscriptions[key] = NetworkSubscription(
                handler: handler
            )
            guard self.connected else { return }
            
            self.request(
                method: method,
                params: params
            ) { result in
                switch result {
                case .success(let data):
                    handler([data])
                case .failure:
                    break
                }
            }
        }
    }
    
    /// Removes a previously-registered subscription.
    ///
    /// - Parameters:
    ///   - method: Subscription method name
    ///   - params: Array of string parameters used
    public func unsubscribe(
        method: String,
        params: [String] = []
    ) {
        let key = self.key(
            method: method,
            params: params
        )
        
        main.async(flags: .barrier) { [weak self] in
            self?.subscriptions.removeValue(forKey: key)
        }
    }
    
    // MARK: - Packet handling
    
    /// Enqueue an already-encoded packet for buffered sending.
    ///
    /// This appends to the send buffer and attempts to flush immediately. If the
    /// packet is too small (and force-send is not enabled), it will schedule a
    /// delayed flush instead.
    private func enqueuePacket(_ packet: Data) {
        write.async { [weak self] in
            guard let self = self else { return }
            
            self.sendBuffer.append(packet)
            
            // Try to flush immediately,
            // schedule a flush otherwise
            if !self.flushSend() {
                self.scheduleFlushSend()
            }
        }
    }
    
    /// Attempts to flush the send buffer immediately
    ///
    /// Returns `true` if data was sent (or at least the send was initiated),
    /// `false` if no send occurred because conditions were not met.
    @discardableResult
    private func flushSend() -> Bool {
        guard connected, !sendBuffer.isEmpty else {
            return false
        }
        
        let payloadSize = sendBuffer.count
        
        // Only send if min packet size is exceeded,
        // or we have exceeded the buffer wait time
        // (or, packet sends are forced via config)
        guard
            config.packetForceSend ||
            payloadSize >= config.packetMinSize ||
            timeSinceFlushSend() >= config.packetMinWait
        else {
            return false
        }
        
        // Compute packet size as the next power of two greater
        // than or equal to the send buffer size. Helps avoid
        // some level of traffic analysis for < TLS 1.3
        var packetSize = config.packetMinSize
        while packetSize < payloadSize {
            packetSize <<= 1
            // In case of overflow
            if packetSize <= 0 { return false }
        }
        
        let padSize = packetSize - payloadSize
        let halfSize = max(config.packetMinSize, packetSize / 2)
       
        // TODO: Actually flush the buffer, pad and send the packet
        
        return true
    }
    
    /// Schedule a future attempt to call `flushSend()`
    ///
    /// This function creates a `sendTask` to fire after the configured `packetMinWait`
    /// to ensure small payloads are not indefinitely buffered.
    private func scheduleFlushSend() {
        guard sendTask == nil else { return }
        
        let remaining = max(0.0, config.packetMinWait - timeSinceFlushSend())
        
        let task = DispatchWorkItem { [weak self] in
            guard let self = self else { return }
            self.sendTask = nil
            self.flushSend()
        }
        
        sendTask = task
        write.asyncAfter(
            deadline: .now() + remaining,
            execute: task
        )
    }

    /// Cancels any scheduled send flush task
    private func cancelFlushSend() {
        sendTask?.cancel()
        sendTask = nil
    }
    
    /// Calculates the last time the send buffer was flushed
    private func timeSinceFlushSend() -> TimeInterval {
        let nanos = DispatchTime.now().uptimeNanoseconds &- sendLast.uptimeNanoseconds
        return Double(nanos) / Double(NSEC_PER_SEC)
    }
    
    // MARK: - Helpers
    
    /// Returns an opaque key for the given method + params that can be used to
    /// uniquely identify subscriptions
    ///
    /// The key is an MD5 hex digest of `method + params.joined()`. MD5 is used
    /// purely as a short, deterministic identifier, not for cryptographic purposes.
    private func key(
        method: String,
        params: [String] = []
    ) -> String {
        let serialised = method + params.joined()
        guard let data = serialised.data(using: .utf8) else {
            // Shouldn't ever happen
            return serialised
        }
        
        let hash = Insecure.MD5.hash(data: data)
        return hash.map { String(format: "%02x", $0) }.joined()
    }
    
    // MARK: - Connection Management
    
    /// Sets up and starts the `NWConnection`
    ///
    /// This configures TLS options (including the minimum TLS version and a custom
    /// verification block used for TOFU / pinned-certificate handling) and launches
    /// the connection on the client's `main` queue.
    private func connect() {
        let options = NWProtocolTLS.Options()
        let secOptions = options.securityProtocolOptions
       
        sec_protocol_options_set_min_tls_protocol_version(
            secOptions,
            config.tlsMinVersion
        )
        
        // Custom verification block for CA & self
        // signed certs, runs on the verify queue
        sec_protocol_options_set_verify_block(
            secOptions,
            { [weak self] metadata, trust, callback in
                guard let self = self else {
                    callback(false)
                    return
                }
                
                self.verifyTLS(
                    metadata: metadata,
                    trust: trust,
                    callback: callback
                )
            },
            verify
        )
        
        let parameters = NWParameters(tls: options)
        let endpoint = NWEndpoint.hostPort(
            host: NWEndpoint.Host(host),
            port: NWEndpoint.Port(rawValue: port)!
        )

        connection = NWConnection(to: endpoint, using: parameters)
        connection?.stateUpdateHandler = { [weak self] state in
            self?.handleStateUpdate(state)
        }
        connection?.start(queue: main)
        
        log("Connection initiated")
    }
    
    /// Cancels the connection and resets state
    private func disconnect() {
        connection?.cancel()
        connection = nil
        connected = false
        
        requests.removeAll()
        subscriptions.removeAll()
        
        log("Connection closed")
    }
    
    // MARK: - Network Handlers
    
    // TODO: Handles updates to the connection state.
    private func handleStateUpdate(_ state: NWConnection.State) {
        switch state {
        case .ready:
            log("Connection ready")
            connected = true
            retries = 0
            
        case .failed(let error):
            log("Connection broken: \(error)")
            connected = false
            
        case .cancelled:
            log("Connection terminated")
            connected = false
            
        default:
            break
        }
    }
    
    /// Handles a request timeout firing for a previously-sent request
    private func handleRequestTimeout(_ id: Int) {
        main.async(flags: .barrier) { [weak self] in
            guard let self = self else { return }

            guard
                let context = self.requests.removeValue(forKey: id)
            else { return }

            context.timer?.cancel()
            context.completion(.failure(.requestTimeout))
        }
    }
    
    // MARK: - TLS Verification
   
    /// Verifies the TLS certificate using a TOFU (Trust On First Use) strategy
    ///
    ///  - If the server chain validates against system CAs and a CA trust marker
    ///    is already saved for this host, the connection is accepted
    ///  - If there is a saved pinned certificate for the host, the server's cert
    ///    is compared with the pinned certificate bytes and validated against it
    ///  - On first use:
    ///     - If the server chain is trusted by the system, a CA trust marker is saved
    ///     - If it is not trusted, the leaf certificate is pinned (saved)
    ///
    /// - Parameters:
    ///   - metadata: `sec_protocol_metadata_t` provided by Network framework
    ///   - trust: `sec_trust_t` representing the evaluated trust object
    ///   - callback: Must be called with `true` to accept, `false` to reject
    private func verifyTLS(
        metadata: sec_protocol_metadata_t,
        trust: sec_trust_t,
        callback: @escaping (Bool) -> Void
    ) {
        // Convert sec_trust_t to SecTrustRef for higher-level APIs
        let ref = sec_trust_copy_ref(trust).takeRetainedValue()
        let trusted = SecTrustEvaluateWithError(ref, nil)
        
        // Subsequent connection, we check if
        // host has been marked as CA trusted
        if loadCaTrustMarker() {
            callback(trusted)
            return
        }
        
        guard
            let chain = SecTrustCopyCertificateChain(ref) as? [SecCertificate],
            let certificate = chain.first
        else {
            callback(false)
            return
        }
        
        // Subsequent connection, we check if
        // host has been marked as self signed
        if let pinned = loadPinnedCertificate() {
            SecTrustSetAnchorCertificates(ref, [pinned] as CFArray)
            SecTrustSetAnchorCertificatesOnly(ref, true)
            
            // We explicitly do not want to check
            // hostnames for self signed certs
            let policy = SecPolicyCreateSSL(true, nil)
            SecTrustSetPolicies(ref, [policy] as CFArray)
            
            let serverData = SecCertificateCopyData(certificate) as Data
            let pinnedData = SecCertificateCopyData(pinned) as Data
            
            if serverData != pinnedData {
                callback(false)
                return
            }
            
            if SecTrustEvaluateWithError(ref, nil) {
                callback(true)
            } else {
                deleteCertificateAndTrustMarker()
                callback(false)
            }
            
            return
        }
        
        // First Use (TOFU): No certificate or CA trust marker found
        if trusted {
            callback(saveCaTrustMarker())
        } else {
            callback(savePinnedCertificate(certificate))
        }
    }
    
    // MARK: - Certificate Keychain Storage
    
    /// Saves the provided certificate as the pinned certificate for this host
    ///
    /// - Parameter certificate: Leaf certificate to pin
    /// - Returns: `true` if the certificate was saved successfully
    private func savePinnedCertificate(_ certificate: SecCertificate) -> Bool {
        // Ensure any prior marker or pin is removed before saving
        deleteCertificateAndTrustMarker()

        let data = SecCertificateCopyData(certificate) as Data
        var query = pinnedKeychainQuery
        
        query[kSecValueData as String] = data
        query[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly

        return SecItemAdd(query as CFDictionary, nil) == errSecSuccess
    }

    /// Loads a pinned certificate for the current host from the keychain
    ///
    /// - Returns: A `SecCertificate` if present, otherwise `nil`
    private func loadPinnedCertificate() -> SecCertificate? {
        var query = pinnedKeychainQuery

        query[kSecReturnData as String] = kCFBooleanTrue as Any
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var result: AnyObject?
        
        guard
            SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
            let data = result as? Data,
            let certificate = SecCertificateCreateWithData(nil, data as CFData)
        else {
            return nil
        }
        
        return certificate
    }

    /// Writes a small marker entry into keychain to record that the host's cert
    /// validated against system CAs and can be trusted as a CA-trusted host
    ///
    /// - Returns: `true` on success
    private func saveCaTrustMarker() -> Bool {
        deleteCertificateAndTrustMarker()
        
        var query = caKeychainQuery
        
        // Empty data as a marker value is sufficient
        query[kSecValueData as String] = Data()
        query[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        
        return SecItemAdd(query as CFDictionary, nil) == errSecSuccess
    }

    /// Checks for presence of the CA trust marker for the current host in keychain
    ///
    /// - Returns: `true` if the marker exists
    private func loadCaTrustMarker() -> Bool {
        var query = caKeychainQuery
        
        query[kSecReturnData as String] = kCFBooleanTrue as Any
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        
        return SecItemCopyMatching(query as CFDictionary, nil) == errSecSuccess
    }
    
    /// Deletes both pinned certificate and CA trust marker entries for the current host
    private func deleteCertificateAndTrustMarker() {
        SecItemDelete(pinnedKeychainQuery as CFDictionary)
        SecItemDelete(caKeychainQuery as CFDictionary)
    }
    
    // MARK: - Debug
    
    /// Internal debug logging helper (no-op in release builds)
    private func log(_ message: String) {
        #if DEBUG
        logger.log(level: .debug, "[ElectrumClient] (\(self.host):\(self.port)) --- \(message, privacy: .public)")
        #endif
    }
}
