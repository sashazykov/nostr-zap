# nostr-zap

[![CI](https://github.com/sashazykov/nostr-zap/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/sashazykov/nostr-zap/actions/workflows/ci.yml)
[![Gem Version](https://badge.fury.io/rb/nostr-zap.svg)](https://rubygems.org/gems/nostr-zap)

A Ruby toolkit for NOSTR [NIP-57](https://github.com/nostr-protocol/nips/blob/master/57.md) Lightning Zaps. Validate zap requests, build zap receipts, publish to relays.

No Rails dependency required.

## Installation

Add to your Gemfile:

```ruby
gem 'nostr-zap'
```

## Components

| Class                             | Purpose                                                               |
| --------------------------------- | --------------------------------------------------------------------- |
| `NostrZap::Crypto`                | Stateless BIP-340 Schnorr cryptography (sign, verify, key derivation) |
| `NostrZap::KeyPair`               | Holds a private/public key pair, convenience signing                  |
| `NostrZap::Event`                 | NIP-01 event: build, sign, verify, serialize                          |
| `NostrZap::Zap::RequestValidator` | Validate kind-9734 zap requests (NIP-57)                              |
| `NostrZap::Zap::ReceiptBuilder`   | Build kind-9735 zap receipts (NIP-57)                                 |
| `NostrZap::RelayClient`           | Publish events to relays via WebSocket (concurrent)                   |
| `NostrZap::RelayUrlValidator`     | SSRF-safe relay URL validation                                        |

## Usage

### Key Management

```ruby
# Generate a new key pair
key_pair = NostrZap::KeyPair.generate
key_pair.public_key_hex  # => "abc123..."

# From an existing private key
key_pair = NostrZap::KeyPair.new("deadbeef" * 8)

# Low-level crypto
NostrZap::Crypto.generate_private_key       # => "64-char hex"
NostrZap::Crypto.derive_public_key(priv)    # => "64-char hex"
NostrZap::Crypto.valid_private_key?(hex)    # => true/false
```

### Building and Signing Events

```ruby
event = NostrZap::Event.new(kind: 1, content: "hello", tags: [])
event.sign(key_pair)

event.to_h
# => { "id" => "...", "pubkey" => "...", "created_at" => 1234567890,
#      "kind" => 1, "tags" => [], "content" => "hello", "sig" => "..." }
```

### Verifying Events

```ruby
event = NostrZap::Event.from_h(parsed_hash)
event.id_valid?        # recomputes ID from payload
event.signature_valid? # verifies BIP-340 signature
```

### Validating Zap Requests

```ruby
validator = NostrZap::Zap::RequestValidator.new(
  zap_request_json,
  verify_signatures: true  # set false to skip sig check (e.g. in tests)
)

if validator.valid?
  validator.recipient_pubkey  # => "hex pubkey"
  validator.relay_urls        # => ["wss://relay.example.com"]
  validator.amount_msats      # => 1000
  validator.zapped_event_id   # => "hex event id" or nil
else
  validator.errors  # => ["Invalid kind: expected 9734, got 1"]
end
```

### Building Zap Receipts

```ruby
builder = NostrZap::Zap::ReceiptBuilder.new(
  zap_request_json: original_zap_request_json,
  bolt11_invoice:   "lnbc10n1...",
  key_pair:         key_pair,
  paid_at:          Time.now,  # optional, defaults to now
  preimage:         "abc..."   # optional
)

event = builder.build       # => NostrZap::Event (kind 9735, signed)
relays = builder.relay_urls # => relay URLs from the original zap request
```

### Publishing to Relays

```ruby
client = NostrZap::RelayClient.new(
  timeout: 10,          # connection timeout in seconds (default: 10)
  logger:  Rails.logger  # optional, any object responding to #error
)

# Publish to multiple relays concurrently
results = client.publish_event(
  event:      event.to_h,
  relay_urls: ["wss://relay1.example.com", "wss://relay2.example.com"]
)
# => { "wss://relay1.example.com" => { success: true, message: "Published" },
#      "wss://relay2.example.com" => { success: false, message: "rate-limited" } }

# Publish to a single relay
result = client.publish_to_relay(
  event:     event.to_h,
  relay_url: "wss://relay.example.com"
)
```

### Relay URL Validation

```ruby
error = NostrZap::RelayUrlValidator.validate("wss://relay.example.com")
# => nil (valid)

error = NostrZap::RelayUrlValidator.validate("ws://localhost")
# => "Invalid relay URL scheme 'ws' (only wss is allowed): ws://localhost"

error = NostrZap::RelayUrlValidator.validate("wss://192.168.1.1")
# => "Relay URL points to a private/reserved address: wss://192.168.1.1"
```

Blocked IP ranges: `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, `0.0.0.0/8`, `::1`, `fc00::/7`, `fe80::/10`.

## Error Classes

```
NostrZap::Error              # base
  NostrZap::ConfigurationError
  NostrZap::InvalidKeyError
  NostrZap::SigningError
  NostrZap::RelayClient::PublishError
```

## Dependencies

- [bip-schnorr](https://rubygems.org/gems/bip-schnorr) ~> 0.7 -- BIP-340 Schnorr signatures
- [concurrent-ruby](https://rubygems.org/gems/concurrent-ruby) ~> 1.0 -- concurrent relay publishing
- [websocket](https://rubygems.org/gems/websocket) ~> 1.0 -- WebSocket handshake and framing

## Development

```sh
cd gems/nostr-zap
bundle install
bundle exec rspec       # 86 specs
bundle exec rubocop
```

## License

MIT
