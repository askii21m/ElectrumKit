import Foundation
import CryptoKit
import Security
import Network

#if DEBUG
import os.log
#endif

// MARK: - Constants

/// A single ASCII newline byte (`\n`) used to terminate packets
///
/// - Important: This is always ASCII `0x0A`.
fileprivate let newline: UInt8 = 0x0A

/// A single ASCII space byte (`' '`) used to pad packets
///
/// - Important: This is always ASCII `0x20`.
fileprivate let space: UInt8 = 0x20

/// A set of valid JSON-RPC terminators
///
/// > Important: These are always:
/// > - `}\n: (0x20, 0x0A)`
/// > - `]\n: (0x5D, 0x0A)`
fileprivate let terminators: Set<Data> = [
    Data([0x7D, 0x0A]),
    Data([0x5D, 0x0A])
]

// MARK: - ElectrumError

/// Errors thrown by the Electrum client
public enum ElectrumError: Error, Equatable {
    
    /// The network connection was closed before the request could complete
    case connectionClosed
    
    /// The request exceeded the configured timeout interval
    case requestTimeout
    
    /// The client has reached its configured concurrent request limit
    case requestLimit
    
    /// The request could not be encoded to JSON
    case requestNoncodable
    
    /// The response was invalid and contained no decodable error information
    case responseInvalid
    
    /// The response contained a JSON-RPC error
    ///
    /// - Parameters:
    ///   - code: The error code returned by the server.
    ///   - message: A descriptive error message.
    case responseError(code: Int, message: String)
}

// MARK: - ElectrumConfig

/// Electrum client configuration
public struct ElectrumConfig {
    
    /// The time interval in seconds between keepalive ping messages
    ///
    /// The client uses ping messages to prevent idle timeouts.
    public let pingInterval: TimeInterval
    
    /// The maximum number of concurrent requests allowed
    ///
    /// When this limit is reached, new requests will fail with ``ElectrumError/requestLimit``.
    public let requestLimit: Int
    
    /// The minimum packet size in bytes before flushing the send buffer
    ///
    /// The client pads RPC payloads up to the next power of two that is greater than
    /// or equal to this value. This helps protect against some traffic analysis attacks.
    public let packetMinSize: Int
    
    /// The minimum time interval to wait before flushing the send buffer.
    ///
    /// Small packets will be buffered until this interval elapses or ``ElectrumConfig/packetMinSize``
    /// is exceeded, unless ``ElectrumConfig/packetForceSend`` is enabled.
    public let packetMinWait: TimeInterval
    
    /// A Boolean value that determines whether to bypass buffering and send immediately
    ///
    /// When `true`, all packets are sent immediately regardless of ``ElectrumConfig/packetMinSize``.
    /// and ``ElectrumConfig/packetMinWait`` settings.
    public let packetForceSend: Bool
    
    /// The minimum TLS protocol version to accept
    ///
    /// - Important: TLS versions lower than TLS 1.2 are deprecated and should
    ///              not be used. Use `.TLSv12` or higher.
    public let tlsMinVersion: tls_protocol_version_t
    
    /// The keychain service identifier for persisting TLS certificates and trust markers
    public let tlsCertPath: String
    
    /// The initial delay in seconds before attempting the first reconnection
    ///
    /// This delay is used as the base for exponential backoff calculations.
    public let reconnectDelay: TimeInterval
    
    /// The maximum delay in seconds between reconnection attempts
    ///
    /// Prevents exponential backoff from growing indefinitely.
    public let reconnectMaxDelay: TimeInterval
    
    /// The multiplier applied to the delay after each failed reconnection attempt
    ///
    /// Each successive reconnection delay is multiplied by this value, creating
    /// exponential backoff behavior.
    public let reconnectMultiplier: Double
    
    /// The random jitter factor applied to reconnection delays
    ///
    /// A random value between `-reconnectJitter` and `+reconnectJitter`
    /// (as a fraction of the delay) is added to each reconnection delay to prevent
    ///  thundering herd problems.
    public let reconnectJitter: Double
   
    /// Creates a new Electrum client configuration.
    ///
    /// - Parameters:
    ///   - pingInterval: The interval between ping messages. Defaults to `30.0` seconds
    ///   - requestLimit: The maximum number of concurrent requests. Defaults to `100`
    ///   - packetMinSize: The minimum packet size in bytes. Defaults to `1024`
    ///   - packetForceSend: Whether to force immediate sends. Defaults to `false`
    ///   - packetMinWait: The minimum wait time before flushing. Defaults to `1.0` second
    ///   - tlsMinVersion: The minimum TLS version. Defaults to `.TLSv12`
    ///   - tlsCertPath: The keychain service path. Defaults to `"electrum.client.certificates"`
    ///   - reconnectDelay: The initial reconnection delay. Defaults to `1.0` second
    ///   - reconnectMaxDelay: The maximum reconnection delay. Defaults to `60.0` seconds
    ///   - reconnectMultiplier: The exponential backoff multiplier. Defaults to `2.0`
    ///   - reconnectJitter: The jitter factor. Defaults to `0.1`
    public init(
        pingInterval: TimeInterval = 30.0,
        requestLimit: Int = 100,
        packetMinSize: Int = 1024,
        packetForceSend: Bool = false,
        packetMinWait: TimeInterval = 1.0,
        tlsMinVersion: tls_protocol_version_t = .TLSv12,
        tlsCertPath: String = "electrum.client.certificates",
        reconnectDelay: TimeInterval = 1.0,
        reconnectMaxDelay: TimeInterval = 60.0,
        reconnectMultiplier: Double = 2.0,
        reconnectJitter: Double = 0.1
    ) {
        self.pingInterval = pingInterval
        self.requestLimit = requestLimit
        
        self.packetMinSize = packetMinSize
        self.packetMinWait = packetMinWait
        self.packetForceSend = packetForceSend
        
        self.tlsMinVersion = tlsMinVersion
        self.tlsCertPath = tlsCertPath
        
        self.reconnectDelay = reconnectDelay
        self.reconnectMaxDelay = reconnectMaxDelay
        self.reconnectMultiplier = reconnectMultiplier
        self.reconnectJitter = reconnectJitter
    }
}

// MARK: - AnyCodable

/// A type-erased wrapper for encoding and decoding heterogeneous JSON values.
///
/// This type supports the following JSON value types:
/// - Primitives: `Int`, `Double`, `String`, `Bool`
/// - Collections: `Array`, `Dictionary`
/// - Null values: `NSNull`
struct AnyCodable: Codable {
    
    /// The underlying value
    let value: Any
    
    /// Creates a type-erased codable wrapper around the given value
    ///
    /// - Parameter value: The value to wrap
    init(_ value: Any) {
        self.value = value
    }
    
    /// Decodes a value from a single value container
    ///
    /// - Parameter decoder: The decoder to read data from
    /// - Throws: `DecodingError.dataCorruptedError` if the value is not one of the
    ///         supported types
    ///
    /// This function decodes the single value container based on its runtime type:
    /// 1. Integer values
    /// 2. Floating-point values
    /// 3. String values
    /// 4. Boolean values
    /// 5. Array values (recursively decoded as `[AnyCodable]`)
    /// 6. Dictionary values (recursively decoded as `[String: AnyCodable]`)
    /// 7. Null values
    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let int = try? container.decode(Int.self) {
            value = int
        } else if let double = try? container.decode(Double.self) {
            value = double
        } else if let string = try? container.decode(String.self) {
            value = string
        } else if let bool = try? container.decode(Bool.self) {
            value = bool
        } else if let array = try? container.decode([AnyCodable].self) {
            value = array.map { $0.value }
        } else if let dict = try? container.decode([String: AnyCodable].self) {
            value = dict.mapValues { $0.value }
        } else if container.decodeNil() {
            value = NSNull()
        } else {
            throw DecodingError.dataCorruptedError(
                in: container,
                debugDescription: "Could not decode value"
            )
        }
    }
    
    /// Encodes the wrapped value to a single value container
    ///
    /// - Parameter encoder: The encoder to write data to
    /// - Throws: `EncodingError.invalidValue` if the value is not one of the
    ///         supported types
    ///
    /// This function encodes the wrapped value based on its runtime type:
    /// 1. Integer values (`Int`)
    /// 2. Floating-point values (`Double`)
    /// 3. String values (`String`)
    /// 4. Boolean values (`Bool`)
    /// 5. Array values (recursively encoded as `[AnyCodable]`)
    /// 6. Dictionary values (recursively encoded as `[String: AnyCodable]`)
    /// 7. Null values (`NSNull`)
    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch value {
        case let int as Int:
            try container.encode(int)
        case let double as Double:
            try container.encode(double)
        case let string as String:
            try container.encode(string)
        case let bool as Bool:
            try container.encode(bool)
        case let array as [Any]:
            try container.encode(array.map { AnyCodable($0) })
        case let dict as [String: Any]:
            try container.encode(dict.mapValues { AnyCodable($0) })
        case is NSNull:
            try container.encodeNil()
        default:
            throw EncodingError.invalidValue(value, EncodingError.Context(
                codingPath: encoder.codingPath,
                debugDescription: "Cannot encode value of type \(type(of: value))"
            ))
        }
    }
}

// MARK: - JSON-RPC Types

/// An encodable JSON-RPC 2.0 request
struct RPCRequest: Encodable {
    
    /// This property is always `"2.0"` to comply with JSON-RPC 2.0 specification.
    let jsonrpc: String = "2.0"
    
    /// The name of the remote method to invoke
    let method: String
    
    /// The parameters to pass to the remote method
    let params: AnyCodable
    
    /// A unique identifier for this request
    let id: Int

    /// Creates a new JSON-RPC request.
    ///
    /// - Parameters:
    ///   - method: The method name
    ///   - params: The method parameters as an array
    ///   - id: The request identifier
    init(method: String, params: [Any], id: Int) {
        self.method = method
        self.params = AnyCodable(params)
        self.id = id
    }
}

/// A decodable JSON-RPC 2.0 response
struct RPCResponse: Decodable {
    
    /// The JSON-RPC protocol version identifier
    let jsonrpc: String?
    
    /// The result of the remote method invocation, if successful
    let result: AnyCodable?
    
    /// The error that occurred, if the invocation failed
    let error: RPCError?
    
    /// The identifier matching the original request
    let id: Int?
}

/// A decodeable JSON-RPC 2.0 Notification
struct RPCNotificaton: Decodable {
    
    /// The JSON-RPC protocol version identifier
    let jsonrpc: String?
    
    /// The notification method
    let method: String
    
    /// The parameters included with the notification
    ///
    /// In the `Electrum` protocol, notifications follow a specific structure
    /// where the subscription parameters are followed by the notification data
    let params: AnyCodable
}

/// A decodable JSON-RPC 2.0 error object
struct RPCError: Decodable {
    
    /// A numeric error code
    let code: Int
    
    /// A human-readable error message
   let message: String
   
   /// Additional error data, if provided
   let data: AnyCodable?
}

// MARK: - ElectrumClient

/// A lightweight client for Electrum servers
///
/// `ElectrumClient` manages a single network connection to an Electrum server using
/// the Network framework. It supports:
/// - Request/response RPC calls with optional timeouts
/// - Persistent server subscriptions that survive reconnection
/// - TLS with Trust On First Use (TOFU) certificate pinning
/// - Traffic obfuscation through packet padding
///
///
/// ## Thread Safety
///
/// All public functions are thread-safe and can be called from any queue. Internal
/// synchronization is handled automatically.
public final class ElectrumClient {
    
    // MARK: - Properties
    
    #if DEBUG
    /// Logger is only used in DEBUG builds
    private let logger: Logger = Logger(subsystem: "electrum", category: "client")
    #endif

    /// The remote hostname to connect to
    private let host: String
    
    /// The remote port to connect to.
    private let port: UInt16
    
    /// The configuration for this client
    private let config: ElectrumConfig
    
    /// A scheduled task to flush the send buffer after a delay
    private var sendTask: DispatchWorkItem? = nil
    
    /// The timestamp of the last send buffer flush
    private var sendLast: DispatchTime = .now()
    
    /// Buffered outgoing data awaiting transmission
    private var sendBuffer: Data = Data()
    
    /// Buffered incoming data awaiting processing
    private var receiveBuffer: Data = Data()
    
    /// The next request identifier to assign
    private var requestId: Int = 1
    
    /// Outstanding requests awaiting responses, keyed by request ID
    private var requests: [Int: NetworkRequest] = [:]
    
    /// Active subscriptions, keyed by a hash of the method and parameters
    private var subscriptions: [String: NetworkSubscription] = [:]
    
    /// Keychain query parameters for pinned certificates
    private let pinnedKeychainQuery: [String: Any]
    
    /// Keychain query parameters for CA trust markers
    private let caKeychainQuery: [String: Any]

    /// The underlying network connection
    private var connection: NWConnection?
    
    /// The network path monitor
    private var monitor: NWPathMonitor?
    
    /// The last observed network path status
    private var pathLast: NWPath.Status?
    
    /// The current connection status
    private var status: ElectrumStatus = .disconnected
    
    /// The number of reconnection attempts made
    private var reconnectAttempts: Int = 0
    
    /// A scheduled task to attempt reconnection
    private var reconnectTask: DispatchWorkItem? = nil
    
    /// A scheduled timer for sending periodic ping messages
    private var pingTask: DispatchSourceTimer? = nil

    /// Queue for network operations and state management
    private let network: DispatchQueue
    
    /// Queue for processing received data
    private let read: DispatchQueue
    
    /// Queue for invoking completion handlers
    private let callback: DispatchQueue
    
    // MARK: - Internal helper types
    
    /// The connection status of the client
    private enum ElectrumStatus {
        
        /// The client has been explicitly stopped
        case stopped
        
        /// The client is disconnected and not yet attempting to connect
        case disconnected
        
        /// The client is attempting to establish a connection
        case connecting
        
        /// The client has an active connection to the server
        case connected
    }
    
    /// Context for an active subscription
    private struct NetworkSubscription {

        /// The subscription method name
        let method: String
        
        /// The parameters for the subscription
        let params: [Any]
        
        /// The handler invoked when notifications are received
        let handler: ([Any]) -> Void
    }
    
    /// Context for an outstanding request
    private struct NetworkRequest {
        
        /// The completion handler to invoke with the result
        let completion: (Result<Any, ElectrumError>) -> Void
        
        /// An optional timer that triggers timeout handling
        let timer: DispatchSourceTimer?
    }
    
    /// Creates a new Electrum client
    ///
    /// - Parameters:
    ///   - host: The remote hostname to connect to
    ///   - port: The remote port to connect to
    ///   - config: The client configuration
    public init(
        host: String,
        port: UInt16,
        config: ElectrumConfig = ElectrumConfig()
    ) {
        self.host = host
        self.port = port
        self.config = config
        
        network = DispatchQueue(label: "\(host).network")
        read = DispatchQueue(label: "\(host).read")
        callback = DispatchQueue(label: "\(host).callback")
        
        // Base queries used for saving certificates + markers to the keychain
        caKeychainQuery = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "\(config.tlsCertPath).ca",
            kSecAttrAccount as String: host
        ]
        pinnedKeychainQuery = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "\(config.tlsCertPath).pinned",
            kSecAttrAccount as String: host,
        ]
    }
    
    /// Cleans up resources when the client is deallocated
    ///
    /// Ensures the connection is properly terminated and all resources are released.
    deinit {
        stop()
    }
    
    // MARK: - Public API
    
    /// Starts the client and initiates a connection to the server
    ///
    /// This function is asynchronous and returns immediately. Connection state changes
    /// can be observed through the lifecycle of individual requests and subscriptions.
    ///
    /// This function is safe to call from any queue.
    public func start() {
        network.async { [weak self] in
            self?.connect()
        }
    }
    
    /// Stops the client and gracefully terminates the connection
    ///
    /// All outstanding requests will fail with ``ElectrumError/connectionClosed``.
    /// Subscriptions will be removed and must be re-registered after a subsequent ``start()``.
    ///
    /// This method is safe to call from any queue.
    public func stop() {
        network.async { [weak self] in
            self?.disconnect()
        }
    }
    
    /// Sends a JSON-RPC request to the server
    ///
    /// - Parameters:
    ///   - method: The remote method name to invoke
    ///   - params: An array of parameters to pass to the method. Defaults to an empty array
    ///   - timeout: An optional timeout interval in seconds. If the response is not received
    ///              within this interval, completion is called with ``ElectrumError/requestTimeout``
    ///   - completion: A completion handler called with the result of the request
    ///
    /// The completion handler is always invoked on an internal serial queue. If you need
    /// to update UI or perform other main-thread work, dispatch to the main queue explicitly.
    ///
    public func request(
        method: String,
        params: [Any] = [],
        timeout: TimeInterval? = nil,
        completion: @escaping (Result<Any, ElectrumError>) -> Void
    ) {
        network.async { [weak self] in
            guard let self = self else { return }

            // Ensure connection is open
            guard connection != nil else {
                self.log("Request \"\(method)\" failed: connection closed")
                self.callback.async {
                    completion(.failure(.connectionClosed))
                }
                return
            }
            
            // Enforce request concurrency limit
            guard self.requests.count < config.requestLimit else {
                self.log("Request \"\(method)\" failed: request limit reached")
                self.callback.async {
                    completion(.failure(.requestLimit))
                }
                return
            }
            
            let currentId = self.requestId
            self.requestId += 1
        
            var timer: DispatchSourceTimer? = nil
            if let timeout = timeout {
                // Start the countdown for the request timeout
                let source = DispatchSource.makeTimerSource(queue: self.network)
                source.schedule(deadline: .now() + timeout)
                source.setEventHandler { [weak self] in
                    self?.handleRequestTimeout(currentId)
                }
                
                source.resume()
                timer = source
            }
            
            let request = RPCRequest(
                method: method,
                params: params,
                id: currentId
            )
            
            self.log("Requesting { \"\(method)\", \(params) }")
            
            // Encode JSON payload
            let data = try? JSONEncoder().encode(request)
            guard var data = data, !data.isEmpty else {
                self.log("Failed to encode { \"\(method)\", \(params) }")
                self.callback.async {
                    completion(.failure(.requestNoncodable))
                }
                return
            }
            
            // Store the request context so responses
            // and their timeouts can be correlated
            self.requests[currentId] = NetworkRequest(
                completion: completion,
                timer: timer
            )
            
            // Each RPC call MUST be terminated by
            // a single newline to delimit messages
            data.append(newline)
            self.enqueuePacket(data)
        }
    }
    
    /// Subscribes to server notifications for a given method and parameters
    ///
    /// - Parameters:
    ///   - method: The subscription method name
    ///   - params: An array of parameters for the subscription. Defaults to an empty array
    ///   - handler: A handler invoked each time a notification is received for this subscription
    ///
    /// Subscriptions persist across reconnections. When the connection is re-established,
    /// the client automatically resubscribes to all registered subscriptions.
    ///
    /// The handler receives an array containing the notification data from the server.
    public func subscribe(
        method: String,
        params: [Any] = [],
        handler: @escaping ([Any]) -> Void
    ) {
        let key = self.key(
            method: method,
            params: params
        )
        
        network.async { [weak self] in
            guard let self = self else { return }

            // Subscriptions can be keyed in without an active connection
            // All subscriptions will be re-established on reconnect
            self.subscriptions[key] = NetworkSubscription(
                method: method,
                params: params,
                handler: handler
            )
            guard connection != nil, self.status == .connected else { return }
            
            self.request(
                method: method,
                params: params
            ) { [weak self] result in
                guard let self = self else { return }
                switch result {
                case .success(let data):
                    self.log("Subscribed to (\(method), \(params))")
                    handler(params + [data])
                case .failure(let error):
                    self.log("Subscription to (\(method), \(params)) failed: \(error)")
                }
            }
        }
    }
    
    /// Removes a previously-registered subscription.
    ///
    /// - Parameters:
    ///   - method: The subscription method name.
    ///   - params: The array of parameters originally used to subscribe.
    public func unsubscribe(
        method: String,
        params: [Any] = []
    ) {
        let key = self.key(
            method: method,
            params: params
        )
        
        network.async { [weak self] in
            self?.subscriptions.removeValue(forKey: key)
        }
    }
    
    // MARK: - Packet handling
    
    /// Enqueues an encoded packet for buffered transmission
    ///
    /// - Parameter packet: The packet data to enqueue
    ///
    /// This function appends the packet to the send buffer and attempts to flush immediately.
    /// If conditions for sending are not met, a delayed flush is scheduled instead.
    private func enqueuePacket(_ packet: Data) {
        network.async { [weak self] in
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
    /// - Returns: `true` if data was sent, `false` otherwise
    ///
    /// Data is sent only if:
    /// - The buffer size exceeds ``ElectrumConfig/packetMinSize``
    /// - The time elapsed since the last send is over ``ElectrumConfig/packetMinWait``
    /// - The ``ElectrumConfig/packetForceSend`` flag is enabled
    /// is enabled.
    ///
    /// The buffer is padded to the next power of two to help prevent basic traffic analysis.
    /// This implements the same logic as Electrum's `PaddedRSTransport`.
    @discardableResult
    private func flushSend() -> Bool {
        guard
            let connection = connection,
            self.status == .connected,
            !sendBuffer.isEmpty
        else {
            return false
        }
        
        let largePayloadSize = sendBuffer.count
        
        // Only send if min packet size is exceeded,
        // or we have exceeded the buffer wait time
        // (or, packet sends are forced via config)
        guard
            config.packetForceSend ||
            largePayloadSize >= config.packetMinSize ||
            timeSinceFlushSend() >= config.packetMinWait
        else {
            return false
        }
        
        // Ensure the last two bytes are in the terminators
        // set - e.g., the buffer ends in '}\n' or ']\n'
        guard terminators.contains(sendBuffer.suffix(2)) else { return false }
        
        /*
         * Same logic as Electrum's PaddedRSTransport, there
         * are two options for flushing the send buffer:
         *
         * 1. Padding to the next power of two, creating a
         *    "large" packet, flushes the full send buffer
         *
         * 2. OR, if the majority of the message would be,
         *    padding, defer sending some messages and
         *    create a packetwith half of that size
         */
        
        // (1) Compute "large" size as the next power of two
        // greater than the send buffer size. Helps avoid
        // some level of traffic analysis for < TLS 1.3
        var largePacketSize = config.packetMinSize
        while largePacketSize <= largePayloadSize {
            largePacketSize <<= 1
            // In case of overflow
            if largePacketSize <= 0 { return false }
        }
        let largePadSize = largePacketSize - largePayloadSize
        
        // (2) Compute "small" size as half the large packet size
        let smallPacketSize = max(
            config.packetMinSize,
            largePacketSize / 2
        )
        var smallPayloadSize: Int?
        
        if let idx = sendBuffer.prefix(smallPacketSize).lastIndex(of: newline) {
            // +1 to include newline
            smallPayloadSize = idx + 1
        }
        let smallPadSize = smallPayloadSize.map { smallPacketSize - $0 } ?? Int.max
        
        let useLarge = (config.packetForceSend || largePadSize <= smallPadSize)
        let (packetSize, packetPad): (Int, Int) = {
            // (2) Flush some, defer for later
            if !useLarge, let smallPayloadSize = smallPayloadSize {
                return (smallPayloadSize, smallPadSize)
            }
            // (1) Flush all
            return (largePayloadSize, largePadSize)
        }()
        
        // .subdata() will crash if we don't guard the range
        guard
            packetSize >= 2,
            packetSize <= largePayloadSize,
            packetPad >= 0
        else { return false }
        
        let terminator = sendBuffer.subdata(in: (packetSize - 2)..<packetSize)
        guard terminators.contains(terminator) else { return false }
        
        let prefix = sendBuffer.subdata(in: 0..<(packetSize - 2))
        let padding = Data(
            repeating: space,
            count: max(0, packetPad)
        )
        
        // Build the final packet
        var out = Data()
        out.reserveCapacity(
            prefix.count +
            padding.count +
            terminator.count
        )
        out.append(prefix)
        out.append(padding)
        out.append(terminator)
        
        // Send and update buffer in completion
        // handler (back on the write queue)
        connection.send(
            content: out,
            completion: .contentProcessed({ [weak self] error in
                if let error = error {
                    self?.log("Send error: \(error)")
                }
            })
        )
        
        sendLast = DispatchTime.now()
        if packetSize <= sendBuffer.count {
            sendBuffer.removeSubrange(0..<packetSize)
            scheduleFlushSend()
        } else {
            sendBuffer.removeAll()
            cancelFlushSend()
        }
        
        return true
    }
   
    /// Schedules a delayed flush attempt
    ///
    /// Creates a dispatch work item that will call `flushSend()` after the remaining
    /// wait time has elapsed.
    private func scheduleFlushSend() {
        guard sendTask == nil else { return }
        
        let remaining = max(0.0, config.packetMinWait - timeSinceFlushSend())
        
        let task = DispatchWorkItem { [weak self] in
            guard let self = self else { return }
            self.sendTask = nil
            self.flushSend()
        }
        
        sendTask = task
        network.asyncAfter(
            deadline: .now() + remaining,
            execute: task
        )
    }

    /// Cancels any scheduled flush task
    private func cancelFlushSend() {
        sendTask?.cancel()
        sendTask = nil
    }
    
    /// Returns the time interval since the last send buffer flush
    ///
    /// - Returns: The elapsed time in seconds
    private func timeSinceFlushSend() -> TimeInterval {
        let nanos = DispatchTime.now().uptimeNanoseconds &- sendLast.uptimeNanoseconds
        return Double(nanos) / Double(NSEC_PER_SEC)
    }
    
    // MARK: - Helpers
    
    /// Generates a unique key for a subscription based on its method and parameters
    ///
    /// - Parameters:
    ///   - method: The subscription method name
    ///   - params: The subscription parameters
    /// - Returns: A hexadecimal string representing the subscription key
    ///
    /// The key is an MD5 hash of the method and serialized parameters. MD5 is used
    /// solely for its speed and deterministic output, not for cryptographic security.
    private func key(
        method: String,
        params: [Any] = []
    ) -> String {
        let serialised = params.map { String(describing: $0) }.joined(separator: ",")
        guard let data = serialised.data(using: .utf8) else {
            // Shouldn't ever happen
            return serialised
        }
        
        let hash = Insecure.MD5.hash(data: data)
        return hash.map { String(format: "%02x", $0) }.joined()
    }
    
    // MARK: - Connection Management
    
    /// Establishes a connection to the server
    ///
    /// Configures TLS with the minimum protocol version and custom certificate
    /// verification using Trust On First Use (TOFU) logic.
    private func connect() {
        guard
            status != .connected,
            status != .connecting
        else { return }
        
        status = .connecting
        
        reconnectTask?.cancel()
        reconnectTask = nil
        
        connection?.cancel()
        connection = nil
        
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
            network
        )
        
        let parameters = NWParameters(tls: options)
        let endpoint = NWEndpoint.hostPort(
            host: NWEndpoint.Host(host),
            port: NWEndpoint.Port(rawValue: port)!
        )

        let newConnection = NWConnection(to: endpoint, using: parameters)
        newConnection.stateUpdateHandler = { [weak self] state in
            self?.handleStateUpdate(state)
        }
        newConnection.start(queue: network)
        connection = newConnection
        
        let newMonitor = NWPathMonitor()
        newMonitor.pathUpdateHandler = { [weak self] path in
            self?.handlePathUpdate(path)
        }
        
        newMonitor.start(queue: network)
        monitor = newMonitor
        
        log("Connection initiating")
    }
    
    /// Terminates the connection and cleans up resources
    ///
    /// All outstanding requests are failed with ``ElectrumError/connectionClosed``.
    private func disconnect() {
        connection?.cancel()
        connection = nil
        
        monitor?.cancel()
        monitor = nil
        
        sendTask?.cancel()
        sendTask = nil
        
        pingTask?.cancel()
        pingTask = nil
        
        reconnectTask?.cancel()
        reconnectTask = nil

        status = .stopped
        reconnectAttempts = 0
        
        // Fail all outstanding requests
        for (_, request) in requests {
            request.timer?.cancel()
            callback.async {
                request.completion(.failure(.connectionClosed))
            }
        }
        
        requests.removeAll()
        subscriptions.removeAll()
        
        log("Connection closed")
    }
    
    /// Begins the receive loop to continuously read data from the server
    ///
    /// This function recursively calls itself to maintain an ongoing receive operation.
    private func startReceiving() {
        connection?.receive(
            minimumIncompleteLength: 1,
            maximumLength: 65536,
            completion: { [weak self] data, _, isComplete, error in
                guard let self = self else { return }
                
                if let error = error {
                    self.log("Receive error: \(error)")
                }
                
                if let data = data, !data.isEmpty {
                    self.handleReceivedData(data)
                }
                
                if !isComplete {
                    self.startReceiving()
                }
            }
        )
    }
    
    /// Begins periodic ping messages to keep the connection alive
    ///
    /// This function creates a timer that periodically sends keepalive messages
    /// to prevent idle connection timeouts.
    private func startPinging() {
        pingTask?.cancel()
        
        let task = DispatchSource.makeTimerSource(queue: network)
        task.schedule(deadline: .now(), repeating: config.pingInterval)
        task.setEventHandler { [weak self] in
            // Ignore ping response, it's just NULL anyway
            self?.request(method: "server.ping") { _ in }
        }
        task.resume()
        
        pingTask = task
    }
    
    /// Resubscribes to all registered subscriptions after a reconnection
    ///
    /// When the connection is re-established, this function iterates through
    /// all registered subscriptions and sends subscription requests to the server
    /// to restore notification delivery.
    private func resubscribeAll() {
        for subscription in subscriptions.values {
            request(
                method: subscription.method,
                params: subscription.params
            ) { [weak self] result in
                guard let self = self else { return }
                
                switch result {
                case .success(let data):
                    subscription.handler(subscription.params + [data])
                    self.log("Resubscribed to (\(subscription.method), \(subscription.params))")
                case .failure(let error):
                    self.log("Resubscription to (\(subscription.method), \(subscription.params)) failed: \(error)")
                    break
                }
            }
        }
    }
    
    /// Schedules a delayed reconnection attempt
    ///
    /// Creates a dispatch work item that will call `connect()` after the remaining
    /// wait time has elapsed.
    ///
    /// The delay uses exponential backoff starting at ``ElectrumConfig/reconnectDelay``
    /// and multiplying by ``ElectrumConfig/reconnectMultiplier`` for each attempt, capped
    /// at ``ElectrumConfig/reconnectMaxDelay``. Random jitter (``ElectrumConfig/reconnectJitter``)
    /// is applied to prevent thundering herd problems.
    private func scheduleReconnect() {
        guard reconnectTask == nil, status == .disconnected else { return }
        
        let baseDelay = min(
            config.reconnectDelay * pow(config.reconnectMultiplier, Double(reconnectAttempts)),
            config.reconnectMaxDelay
        )
        
        let jitter = baseDelay * config.reconnectJitter * Double.random(in: -1...1)
        let delay = max(baseDelay, baseDelay + jitter)
        
        log("Scheduling reconnect in \(delay) seconds (attempt \(reconnectAttempts))")
        reconnectAttempts += 1
        
        let task = DispatchWorkItem { [weak self] in
            self?.connect()
        }
        
        reconnectTask = task
        network.asyncAfter(
            deadline: .now() + delay,
            execute: task
        )
    }
    
    /// Handles updates to the connection state
    ///
    /// - Parameter state: The new connection state
    private func handleStateUpdate(_ state: NWConnection.State) {
        switch state {
        case .ready:
            status = .connected
            reconnectAttempts = 0

            startReceiving()
            startPinging()
            resubscribeAll()
            
            log("Connection ready")

        case .failed(let error):
            status = .disconnected
            
            pingTask?.cancel()
            pingTask = nil
            
            scheduleReconnect()
            
            log("Connection broken: \(error)")
            
        case .cancelled:
            status = .disconnected
            
            pingTask?.cancel()
            pingTask = nil
            
            log("Connection terminated")
            
        default:
            break
        }
    }
    
    /// Handles updates to the network path
    ///
    /// - Parameter state: The new network path
    private func handlePathUpdate(_ path: NWPath) {
        guard path.status != pathLast else { return }
        pathLast = path.status
        
        if path.status == .unsatisfied {
            log("Network path broken")

            connection?.cancel()
            connection = nil
            
            reconnectTask?.cancel()
            reconnectTask = nil
        } else if path.status == .satisfied, status == .disconnected {
            log("Network path established")
            connect()
        }
    }
    
    /// Handles a request timeout for a previously-sent request
    ///
    /// - Parameter id: The request identifier
    private func handleRequestTimeout(_ id: Int) {
        guard let request = self.requests.removeValue(forKey: id)
        else { return }

        request.timer?.cancel()
        self.callback.async {
            request.completion(.failure(.requestTimeout))
        }
    }
    
    /// Appends newly-received data to the receive buffer and processes complete messages
    ///
    /// - Parameter data: The received data chunk
    ///
    /// Messages are extracted by scanning for newline delimiters. Complete messages
    /// are passed to `processResponse()` for decoding.
    private func handleReceivedData(_ data: Data) {
        read.async { [weak self] in
            guard let self = self else { return }
            
            self.receiveBuffer.append(data)
            
            // Extract newline-delimited messages
            while let range = self.receiveBuffer.range(of: Data([newline])) {
                let data = self.receiveBuffer.subdata(in: 0..<range.lowerBound)
                self.receiveBuffer.removeSubrange(0...range.lowerBound)
                
                if !data.isEmpty {
                    self.processMessage(data)
                }
            }
        }
    }
    
    /// Decodes a JSON-RPC message and dispatches it to the appropriate handler
    ///
    /// - Parameter data: The raw JSON message data
    ///
    /// This function attempts to decode the data as either an `RPCResponse` (for request/response
    /// messages) or an `RPCNotification` (for server-initiated notifications). If the message
    /// is a response with a valid ID, it is passed to `handleResponse()`. If it is a notification,
    /// it is passed to `handleNotification()`.
    private func processMessage(_ data: Data) {
        if
            let response = try? JSONDecoder().decode(RPCResponse.self, from: data),
            let id = response.id
        {
            handleResponse(id: id, response: response)
            return
        } else if
            let notification = try? JSONDecoder().decode(RPCNotificaton.self, from: data)
        {
            handleNotification(notification)
            return
        }
        
        log("Failed to decode message: \(String(data: data, encoding: .utf8) ?? "invalid")")
    }
    
    /// Processes a JSON-RPC response and invokes the corresponding request handler
    ///
    /// - Parameters:
    ///   - id: The request identifier from the original request
    ///   - response: The decoded response object
    ///
    /// - Note: Responses for unknown request IDs are ignored.
    private func handleResponse(id: Int, response: RPCResponse) {
        network.async { [weak self] in
            guard
                let self = self,
                let request = self.requests.removeValue(forKey: id)
            else {
                return
            }
            
            request.timer?.cancel()
            
            callback.async {
                if let error = response.error {
                    request.completion(.failure(.responseError(
                        code: error.code,
                        message: error.message
                    )))
                } else if let result = response.result {
                    request.completion(.success(result.value))
                } else {
                    request.completion(.failure(.responseInvalid))
                }
            }
        }
    }
    
    /// Processes a JSON-RPC notification and invokes the corresponding subscription handler
    ///
    /// - Parameter notification: The decoded notification object
    ///
    /// - Note: Notifications with invalid parameters or no matching subscription are ignored.
    private func handleNotification(_ notification: RPCNotificaton) {
        guard let data = notification.params.value as? [Any], !data.isEmpty else {
            log("Invalid notification: \(notification)")
            return
        }
        
        let params = Array(data.dropLast())
        let key = key(method: notification.method, params: params)
        
        network.async { [weak self] in
            guard
                let self = self,
                let subscription = self.subscriptions[key]
            else {
                return
            }
            
            callback.async {
                subscription.handler(data)
            }
        }
    }
    
    // MARK: - TLS Verification
   
    /// Verifies the TLS certificate using Trust On First Use (TOFU) strategy.
    ///
    /// - Parameters:
    ///   - metadata: The TLS protocol metadata.
    ///   - trust: The trust object to evaluate.
    ///   - callback: A completion handler that must be called with `true` to accept
    ///               the connection or `false` to reject it.
    ///
    /// This function implements a security model where:
    /// 1. If the server's certificate chain validates against system CAs and a CA trust
    ///    marker exists for this host, the connection is accepted.
    /// 2. If a pinned certificate exists for this host, the server's certificate is
    ///    compared against the pinned certificate.
    /// 3. On first connection:
    ///    - If the chain validates against system CAs, a CA trust marker is saved.
    ///    - If CA validation fails, the leaf certificate is pinned for future connections.
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
    
    /// Logs a debug message
    ///
    /// - Parameter message: The message to log
    ///
    /// Logging is only active in debug builds.
    private func log(_ message: String) {
        #if DEBUG
        logger.log(level: .debug, "[ElectrumClient] (\(self.host):\(self.port)) --- \(message, privacy: .public)")
        #endif
    }
}
