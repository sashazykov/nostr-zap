# frozen_string_literal: true

module NostrZap
  # Holds a NOSTR key pair (private + public key) and provides signing convenience.
  #
  # @example From an existing private key
  #   kp = NostrZap::KeyPair.new('deadbeef' * 8)
  #   kp.public_key_hex  # => "abc..."
  #   kp.sign_event(pubkey:, created_at:, kind:, tags:, content:)
  #
  # @example Generate a new key pair
  #   kp = NostrZap::KeyPair.generate
  #
  class KeyPair
    # @return [String] 64-character hex private key
    attr_reader :private_key_hex

    # @param private_key_hex [String] 64-character hex private key
    # @raise [InvalidKeyError] if the key is invalid
    def initialize(private_key_hex)
      Crypto.validate_private_key!(private_key_hex)
      @private_key_hex = private_key_hex
    end

    # Generates a new random key pair.
    #
    # @return [KeyPair]
    def self.generate
      new(Crypto.generate_private_key)
    end

    # The x-only public key (32 bytes, hex) per BIP-340.
    #
    # @return [String] 64-character hex public key
    def public_key_hex
      @public_key_hex ||= Crypto.derive_public_key(@private_key_hex)
    end

    # Signs a NOSTR event and returns the signature.
    #
    # @param event_data [Hash] with keys :pubkey, :created_at, :kind, :tags, :content
    # @return [String] 128-character hex signature
    def sign_event(event_data)
      event_id = Crypto.compute_event_id(**event_data)
      Crypto.sign(event_id, @private_key_hex)
    end
  end
end
