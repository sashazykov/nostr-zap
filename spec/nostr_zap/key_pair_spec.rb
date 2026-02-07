# frozen_string_literal: true

require 'spec_helper'

RSpec.describe NostrZap::KeyPair do
  let(:private_key_hex) { NostrZap::Crypto.generate_private_key }

  describe '.new' do
    it 'accepts a valid private key' do
      kp = described_class.new(private_key_hex)
      expect(kp.private_key_hex).to eq(private_key_hex)
    end

    it 'raises InvalidKeyError for an invalid key' do
      expect { described_class.new('bad') }.to raise_error(NostrZap::InvalidKeyError)
    end
  end

  describe '.generate' do
    it 'creates a key pair with a valid private key' do
      kp = described_class.generate
      expect(NostrZap::Crypto.valid_private_key?(kp.private_key_hex)).to be(true)
    end
  end

  describe '#public_key_hex' do
    it 'returns a 64-character hex string' do
      kp = described_class.new(private_key_hex)
      expect(kp.public_key_hex).to match(/\A[0-9a-f]{64}\z/)
    end
  end

  describe '#sign_event' do
    let(:key_pair) { described_class.new(private_key_hex) }
    let(:event_data) do
      {
        pubkey: key_pair.public_key_hex,
        created_at: 1_609_459_200,
        kind: 1,
        tags: [],
        content: 'hello',
      }
    end

    it 'returns a 128-character hex signature' do
      sig = key_pair.sign_event(event_data)
      expect(sig).to match(/\A[0-9a-f]{128}\z/)
    end

    it 'produces a verifiable signature' do
      sig = key_pair.sign_event(event_data)
      event_id = NostrZap::Crypto.compute_event_id(**event_data)
      expect(NostrZap::Crypto.verify_signature?(event_id, key_pair.public_key_hex, sig)).to be(true)
    end
  end
end
