# frozen_string_literal: true

require 'spec_helper'

RSpec.describe NostrZap::Crypto do
  let(:private_key_hex) { NostrZap::Crypto.generate_private_key }

  describe '.derive_public_key' do
    it 'returns a 64-character hex string' do
      pubkey = described_class.derive_public_key(private_key_hex)
      expect(pubkey).to match(/\A[0-9a-f]{64}\z/)
    end

    it 'returns consistent results for the same key' do
      expect(described_class.derive_public_key(private_key_hex))
        .to eq(described_class.derive_public_key(private_key_hex))
    end

    it 'raises InvalidKeyError for invalid key' do
      expect { described_class.derive_public_key('bad') }
        .to raise_error(NostrZap::InvalidKeyError)
    end
  end

  describe '.compute_event_id' do
    let(:event_data) do
      {
        pubkey: 'a' * 64,
        created_at: 1_609_459_200,
        kind: 1,
        tags: [],
        content: 'hello',
      }
    end

    it 'returns a 64-character hex string' do
      expect(described_class.compute_event_id(**event_data)).to match(/\A[0-9a-f]{64}\z/)
    end

    it 'produces consistent hashes' do
      expect(described_class.compute_event_id(**event_data))
        .to eq(described_class.compute_event_id(**event_data))
    end

    it 'produces different hashes for different data' do
      other = event_data.merge(content: 'different')
      expect(described_class.compute_event_id(**event_data))
        .not_to eq(described_class.compute_event_id(**other))
    end
  end

  describe '.sign and .verify_signature?' do
    let(:public_key_hex) { described_class.derive_public_key(private_key_hex) }
    let(:message_hex) { Digest::SHA256.hexdigest('test message') }

    it 'produces a 128-character hex signature' do
      sig = described_class.sign(message_hex, private_key_hex)
      expect(sig).to match(/\A[0-9a-f]{128}\z/)
    end

    it 'produces a valid signature' do
      sig = described_class.sign(message_hex, private_key_hex)
      expect(described_class.verify_signature?(message_hex, public_key_hex, sig)).to be(true)
    end

    it 'rejects a tampered signature' do
      expect(described_class.verify_signature?(message_hex, public_key_hex, 'a' * 128)).to be(false)
    end
  end

  describe '.generate_private_key' do
    it 'returns a 64-character hex string' do
      expect(described_class.generate_private_key).to match(/\A[0-9a-f]{64}\z/)
    end

    it 'generates unique keys' do
      keys = Array.new(5) { described_class.generate_private_key }
      expect(keys.uniq.size).to eq(5)
    end
  end

  describe '.valid_private_key?' do
    it 'returns true for a valid key' do
      expect(described_class.valid_private_key?(private_key_hex)).to be(true)
    end

    it 'returns false for wrong length' do
      expect(described_class.valid_private_key?('ab' * 16)).to be(false)
    end

    it 'returns false for non-hex' do
      expect(described_class.valid_private_key?('z' * 64)).to be(false)
    end

    it 'returns false for nil' do
      expect(described_class.valid_private_key?(nil)).to be(false)
    end
  end
end
