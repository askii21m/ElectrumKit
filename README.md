# ElectrumKit

**ElectrumKit** is a secure, lightweight and dependency-free Swift client for Electrum servers. 

## Features
- **No external dependencies:** Uses only Apple system frameworks (`Foundation`, `CryptoKit`, `Security`, `Network`)
- **TLS security:** Supports Trust-On-First-Use (TOFU) certificate pinning and system CA verification
- **Privacy:** Packet buffering and padding to help mitigate traffic analysis for < `TLS 1.3`
- **Reliability:** Automatic reconnection with exponential backoff and jitter
- **Thread safety:** All public API functions are safe to call from any dispatch queue

## Requirements
- iOS 15.0+ / macOS 12.0+
- Swift 5.7+

## Usage examples
### Basic Setup
```swift
import ElectrumKit

let client = ElectrumClient(
    host: "blockstream.info",
    port: 700
)

client.start()

// Do stuff...

client.stop()
```

### Making requests
```swift
client.request(
    method: "blockchain.scripthash.get_balance",
    params: [scripthash],
    timeout: 10.0
) { result in
    switch result {
    case .success(let balance):
        print("Balance: \(balance)")
    case .failure(let error):
        print("Error: \(error)")
    }
}
```

### Making subscriptions
```swift
client.subscribe(
    method: "blockchain.headers.subscribe",
    params: []
) { notification in
    print("Received notification: \(notification)")
}
```

## Thread safety
All public methods are thread-safe. Completion handlers are invoked on an internal serial queue.<br>
Importantly, for UI updates, make sure you *explicitly* dispatch to the main queue:
```swift
client.request(method: "server.ping") { result in
    DispatchQueue.main.async {
        // Update UI
    }
}
```

## Contributing

Contributions are welcome. Please submit pull requests or open issues for bugs and feature requests.
