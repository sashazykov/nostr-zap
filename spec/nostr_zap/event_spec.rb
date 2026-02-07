# frozen_string_literal: true

require 'spec_helper'

RSpec.describe NostrZap::Event do
  let(:key_pair) { NostrZap::KeyPair.generate }

  describe '#sign' do
    it 'sets pubkey, id, and sig' do
      event = described_class.new(kind: 1, content: 'hello')
      event.sign(key_pair)

      expect(event.pubkey).to eq(key_pair.public_key_hex)
      expect(event.id).to match(/\A[0-9a-f]{64}\z/)
      expect(event.sig).to match(/\A[0-9a-f]{128}\z/)
    end
  end

  describe '#id_valid?' do
    it 'returns true for a properly signed event' do
      event = described_class.new(kind: 1, content: 'hello')
      event.sign(key_pair)

      expect(event.id_valid?).to be(true)
    end

    it 'returns false when content is tampered' do
      event = described_class.new(kind: 1, content: 'hello')
      event.sign(key_pair)
      event.content = 'tampered'

      expect(event.id_valid?).to be(false)
    end
  end

  describe '#signature_valid?' do
    it 'returns true for a properly signed event' do
      event = described_class.new(kind: 1, content: 'hello')
      event.sign(key_pair)

      expect(event.signature_valid?).to be(true)
    end

    it 'returns false for a tampered signature' do
      event = described_class.new(kind: 1, content: 'hello')
      event.sign(key_pair)
      event.sig = 'a' * 128

      expect(event.signature_valid?).to be(false)
    end

    it 'returns false when fields are missing' do
      event = described_class.new(kind: 1, content: 'hello')
      expect(event.signature_valid?).to be(false)
    end
  end

  describe '.from_h' do
    it 'reconstructs an event from a hash' do
      event = described_class.new(kind: 1, content: 'test', tags: [%w[p abc]])
      event.sign(key_pair)

      restored = described_class.from_h(event.to_h)
      expect(restored.to_h).to eq(event.to_h)
      expect(restored.id_valid?).to be(true)
      expect(restored.signature_valid?).to be(true)
    end
  end

  describe '#to_h' do
    it 'returns a hash with all event fields' do
      event = described_class.new(kind: 1, content: 'test')
      event.sign(key_pair)

      h = event.to_h
      expect(h.keys).to contain_exactly('id', 'pubkey', 'created_at', 'kind', 'tags', 'content', 'sig')
    end
  end
end
