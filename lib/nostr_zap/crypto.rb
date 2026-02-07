# frozen_string_literal: true

require 'schnorr'
require 'securerandom'
require 'digest'
require 'json'

module NostrZap
  # Low-level cryptographic operations for NOSTR (BIP-340 Schnorr over secp256k1).
  #
  # All methods are stateless. For key management, see {KeyPair}.
  #
  # @example
  #   event_id = NostrZap::Crypto.compute_event_id(pubkey:, created_at:, kind:, tags:, content:)
  #   signature = NostrZap::Crypto.sign(message_hex, private_key_hex)
  #   valid = NostrZap::Crypto.verify_signature?(message_hex, public_key_hex, signature_hex)
  #
  module Crypto
  module_function

    # Derives the x-only public key (32 bytes, hex) from a private key.
    #
    # @param private_key_hex [String] 64-character hex private key
    # @return [String] 64-character hex public key (x-only, per BIP-340)
    # @raise [InvalidKeyError] if the private key is invalid
    def derive_public_key(private_key_hex)
      validate_private_key!(private_key_hex)

      private_key_int = private_key_hex.to_i(16)
      public_key_point = (Schnorr::GROUP.generator.to_jacobian * private_key_int).to_affine

      ECDSA::Format::IntegerOctetString.encode(public_key_point.x, Schnorr::GROUP.byte_length).unpack1('H*')
    end

    # Computes a NOSTR event ID (SHA256 of the canonical serialization per NIP-01).
    #
    # @param pubkey [String] 64-char hex public key
    # @param created_at [Integer] Unix timestamp
    # @param kind [Integer] Event kind
    # @param tags [Array] Event tags
    # @param content [String] Event content
    # @return [String] 64-character hex event ID
    def compute_event_id(pubkey:, created_at:, kind:, tags:, content:)
      serialized = [0, pubkey, created_at, kind, tags, content].to_json
      Digest::SHA256.hexdigest(serialized)
    end

    # Signs a hex message using BIP-340 Schnorr.
    #
    # @param message_hex [String] 64-char hex string to sign (typically an event ID)
    # @param private_key_hex [String] 64-char hex private key
    # @return [String] 128-character hex signature
    # @raise [SigningError] if signing fails
    def sign(message_hex, private_key_hex)
      private_key_bytes = [private_key_hex].pack('H*')
      message_bytes = [message_hex].pack('H*')

      signature = Schnorr.sign(message_bytes, private_key_bytes)
      signature.encode.unpack1('H*')
    rescue => e
      raise SigningError, "Failed to sign message: #{e.message}"
    end

    # Verifies a BIP-340 Schnorr signature.
    #
    # @param message_hex [String] 64-char hex message (event ID)
    # @param public_key_hex [String] 64-char hex public key
    # @param signature_hex [String] 128-char hex signature
    # @return [Boolean]
    def verify_signature?(message_hex, public_key_hex, signature_hex)
      message_bytes = [message_hex].pack('H*')
      signature_bytes = [signature_hex].pack('H*')

      Schnorr.valid_sig?(message_bytes, public_key_hex, signature_bytes)
    rescue
      false
    end

    # Generates a random private key suitable for NOSTR/secp256k1.
    #
    # @return [String] 64-character hex private key
    def generate_private_key
      SecureRandom.hex(32)
    end

    # Validates a private key hex string.
    #
    # @param hex [String]
    # @return [Boolean]
    def valid_private_key?(hex)
      return false unless hex.is_a?(String)
      return false unless hex.length == 64
      return false unless hex.match?(/\A[0-9a-f]+\z/i)

      key_int = hex.to_i(16)
      key_int.positive? && key_int < Schnorr::GROUP.order
    end

    # @raise [InvalidKeyError] if the key is invalid
    def validate_private_key!(hex)
      raise InvalidKeyError, 'Private key must be a 64-character hex string' unless valid_private_key?(hex)
    end
  end
end
