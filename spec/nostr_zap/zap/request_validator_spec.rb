# frozen_string_literal: true

require 'spec_helper'

RSpec.describe NostrZap::Zap::RequestValidator do
  subject(:validator) { described_class.new(zap_request_json, verify_signatures: false) }

  before do
    allow(Resolv).to receive(:getaddresses).and_return(['93.184.215.14'])
  end

  let :valid_event do
    pubkey = '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
    created_at = 1_609_459_200
    kind = 9734
    tags = [
      ['p', 'b' * 64],
      ['relays', 'wss://relay1.example.com', 'wss://relay2.example.com'],
      %w[amount 21000]
    ]
    content = ''

    serialized = [0, pubkey, created_at, kind, tags, content].to_json
    event_id = Digest::SHA256.hexdigest(serialized)

    {
      'id' => event_id,
      'pubkey' => pubkey,
      'created_at' => created_at,
      'kind' => kind,
      'tags' => tags,
      'content' => content,
      'sig' => 'a' * 128
    }
  end

  let(:zap_request_json) { valid_event.to_json }

  describe '#valid?' do
    context 'with a valid zap request' do
      it 'returns true' do
        expect(validator.valid?).to be(true)
      end

      it 'has no errors' do
        validator.valid?
        expect(validator.errors).to be_empty
      end
    end

    context 'with invalid JSON' do
      let(:zap_request_json) { 'not valid json' }

      it 'returns false' do
        expect(validator.valid?).to be(false)
      end

      it 'adds an error about invalid JSON' do
        validator.valid?
        expect(validator.errors.first).to match(/Invalid JSON/)
      end
    end

    context 'with missing required fields' do
      let(:zap_request_json) { { 'id' => 'abc' }.to_json }

      it 'returns false' do
        expect(validator.valid?).to be(false)
      end
    end

    context 'with wrong kind' do
      let(:zap_request_json) { valid_event.merge('kind' => 1).to_json }

      it 'returns false' do
        expect(validator.valid?).to be(false)
      end

      it 'adds an error about invalid kind' do
        validator.valid?
        expect(validator.errors.first).to match(/Invalid kind/)
      end
    end

    context 'with non-integer kind' do
      let :zap_request_json do
        event = valid_event.merge('kind' => 9734.0)
        recompute_id(event).to_json
      end

      it 'returns false' do
        expect(validator.valid?).to be(false)
      end

      it 'adds an error about invalid kind' do
        validator.valid?
        expect(validator.errors.first).to match(/Invalid kind/)
      end
    end

    context 'without p tag' do
      let :zap_request_json do
        event = valid_event.dup
        event['tags'] = event['tags'].reject { |tag| tag[0] == 'p' }
        recompute_id(event).to_json
      end

      it 'returns false' do
        expect(validator.valid?).to be(false)
      end
    end

    context 'with malformed p tag value' do
      let :zap_request_json do
        event = valid_event.dup
        event['tags'] = event['tags'].reject { |tag| tag[0] == 'p' }
        event['tags'] << ['p', 'not-a-hex-pubkey']
        recompute_id(event).to_json
      end

      it 'returns false' do
        expect(validator.valid?).to be(false)
      end

      it 'adds an error about p tag format' do
        validator.valid?
        expect(validator.errors.first).to match(/Invalid 'p' tag/)
      end
    end

    context 'with non-string p tag value' do
      let :zap_request_json do
        event = valid_event.dup
        event['tags'] = event['tags'].reject { |tag| tag[0] == 'p' }
        event['tags'] << ['p', 123]
        recompute_id(event).to_json
      end

      it 'returns false' do
        expect(validator.valid?).to be(false)
      end

      it 'adds an error about missing p tag value' do
        validator.valid?
        expect(validator.errors.first).to match(/Missing required 'p' tag/)
      end
    end

    context 'without relays tag' do
      let :zap_request_json do
        event = valid_event.dup
        event['tags'] = event['tags'].reject { |tag| tag[0] == 'relays' }
        recompute_id(event).to_json
      end

      it 'returns false' do
        expect(validator.valid?).to be(false)
      end
    end

    context 'with ws relay URL scheme' do
      let(:zap_request_json) { event_with_relays(['ws://relay.example.com']) }

      it 'returns true' do
        expect(validator.valid?).to be(true)
      end
    end

    context 'with non-websocket relay URL scheme' do
      let(:zap_request_json) { event_with_relays(['http://relay.example.com']) }

      it 'returns false' do
        expect(validator.valid?).to be(false)
      end
    end

    context 'with relay URL pointing to a private IP' do
      let(:zap_request_json) { event_with_relays(['wss://internal.example.com']) }

      before do
        allow(Resolv).to receive(:getaddresses).with('internal.example.com').and_return(['192.168.1.1'])
      end

      it 'returns true' do
        expect(validator.valid?).to be(true)
      end
    end

    context 'with relay URL pointing to localhost over ws' do
      let(:zap_request_json) { event_with_relays(['ws://localhost:4848']) }

      before do
        allow(Resolv).to receive(:getaddresses).with('localhost').and_return(['127.0.0.1'])
      end

      it 'returns true' do
        expect(validator.valid?).to be(true)
      end
    end

    context 'with relay URL that does not resolve' do
      let(:zap_request_json) { event_with_relays(['wss://relay.nostr.bg']) }

      before do
        allow(Resolv).to receive(:getaddresses).with('relay.nostr.bg').and_return([])
      end

      it 'returns true' do
        expect(validator.valid?).to be(true)
      end
    end

    context 'with invalid event ID' do
      let(:zap_request_json) { valid_event.merge('id' => 'a' * 64).to_json }

      it 'returns false' do
        expect(validator.valid?).to be(false)
      end
    end

    context 'with malformed field formats' do
      let(:zap_request_json) { valid_event.merge('id' => 'xyz!').to_json }

      it 'returns false' do
        expect(validator.valid?).to be(false)
      end
    end

    context 'with signature verification enabled' do
      let(:key_pair) { NostrZap::KeyPair.generate }

      let :signed_event do
        pubkey = key_pair.public_key_hex
        created_at = 1_609_459_200
        kind = 9734
        tags = [
          ['p', 'b' * 64],
          ['relays', 'wss://relay1.example.com'],
          ['amount', '21000']
        ]
        content = ''

        event_data = { pubkey: pubkey, created_at: created_at, kind: kind, tags: tags, content: content }
        event_id = NostrZap::Crypto.compute_event_id(**event_data)
        signature = key_pair.sign_event(event_data)

        {
          'id' => event_id,
          'pubkey' => pubkey,
          'created_at' => created_at,
          'kind' => kind,
          'tags' => tags,
          'content' => content,
          'sig' => signature
        }
      end

      context 'with a correctly signed event' do
        subject(:validator) { described_class.new(signed_event.to_json, verify_signatures: true) }

        it { is_expected.to be_valid }
      end

      context 'with a tampered signature' do
        subject(:validator) { described_class.new(tampered.to_json, verify_signatures: true) }

        let(:tampered) { signed_event.merge('sig' => 'a' * 128) }

        it 'returns false' do
          expect(validator.valid?).to be(false)
        end

        it 'adds an error about the signature' do
          validator.valid?
          expect(validator.errors.first).to match(/Invalid signature/)
        end
      end
    end
  end

  describe '#recipient_pubkey' do
    before { validator.valid? }

    it 'returns the pubkey from the p tag' do
      expect(validator.recipient_pubkey).to eq('b' * 64)
    end
  end

  describe '#relay_urls' do
    before { validator.valid? }

    it 'returns the relay URLs from the relays tag' do
      expect(validator.relay_urls).to eq(%w[wss://relay1.example.com wss://relay2.example.com])
    end
  end

  describe '#amount_msats' do
    before { validator.valid? }

    it 'returns the amount in millisatoshis' do
      expect(validator.amount_msats).to eq(21_000)
    end
  end

  describe '#zapped_event_id' do
    before { validator.valid? }

    context 'when e tag is present' do
      let :zap_request_json do
        event = valid_event.dup
        event['tags'] << %w[e event_id_being_zapped]
        recompute_id(event).to_json
      end

      it 'returns the event ID' do
        expect(validator.zapped_event_id).to eq('event_id_being_zapped')
      end
    end

    context 'when e tag is missing' do
      it 'returns nil' do
        expect(validator.zapped_event_id).to be_nil
      end
    end
  end

  def recompute_id(event)
    serialized = [0, event['pubkey'], event['created_at'], event['kind'], event['tags'], event['content']].to_json
    event['id'] = Digest::SHA256.hexdigest(serialized)
    event
  end

  def event_with_relays(relay_urls)
    event = valid_event.dup
    event['tags'] = event['tags'].reject { |tag| tag[0] == 'relays' }
    event['tags'] << ['relays', *relay_urls]
    recompute_id(event).to_json
  end
end
