# frozen_string_literal: true

module NostrZap
  # A NOSTR event (NIP-01).
  #
  # Can be built unsigned and then signed with a {KeyPair}, or constructed
  # from a fully-signed event hash (e.g., parsed from JSON).
  #
  # @example Build and sign a new event
  #   event = NostrZap::Event.new(kind: 1, content: 'hello', tags: [])
  #   event.sign(key_pair)
  #   event.to_h  # => { id: '...', pubkey: '...', ... }
  #
  # @example Parse and verify an existing event
  #   event = NostrZap::Event.from_h(parsed_hash)
  #   event.id_valid?        # recomputes ID from payload
  #   event.signature_valid? # verifies BIP-340 signature
  #
  class Event
    attr_accessor :id, :pubkey, :created_at, :kind, :tags, :content, :sig

    def initialize(kind:, content:, tags: [], pubkey: nil, created_at: nil, id: nil, sig: nil)
      @kind = kind
      @content = content
      @tags = tags
      @pubkey = pubkey
      @created_at = created_at || Time.now.to_i
      @id = id
      @sig = sig
    end

    # Builds an Event from a Hash (string or symbol keys).
    #
    # @param hash [Hash]
    # @return [Event]
    def self.from_h(hash)
      h = hash.transform_keys(&:to_s)
      new(
        id: h['id'],
        pubkey: h['pubkey'],
        created_at: h['created_at'],
        kind: h['kind'],
        tags: h['tags'] || [],
        content: h['content'] || '',
        sig: h['sig'],
      )
    end

    # Signs this event with the given key pair.
    # Sets pubkey, id, and sig.
    #
    # @param key_pair [KeyPair]
    # @return [self]
    def sign(key_pair)
      @pubkey = key_pair.public_key_hex
      @id = computed_id
      @sig = key_pair.sign_event(event_data)
      self
    end

    # Computes what the event ID should be based on the current payload.
    #
    # @return [String] 64-char hex
    def computed_id
      Crypto.compute_event_id(**event_data)
    end

    # Checks if the stored ID matches the computed ID.
    #
    # @return [Boolean]
    def id_valid?
      @id == computed_id
    end

    # Verifies the BIP-340 Schnorr signature against the event ID and pubkey.
    #
    # @return [Boolean]
    def signature_valid?
      return false unless @id && @pubkey && @sig

      Crypto.verify_signature?(@id, @pubkey, @sig)
    end

    # Serializes to a Hash suitable for JSON encoding / relay transmission.
    #
    # @return [Hash]
    def to_h
      {
        'id' => @id,
        'pubkey' => @pubkey,
        'created_at' => @created_at,
        'kind' => @kind,
        'tags' => @tags,
        'content' => @content,
        'sig' => @sig,
      }
    end

  private

    def event_data
      { pubkey: @pubkey, created_at: @created_at, kind: @kind, tags: @tags, content: @content }
    end
  end
end
