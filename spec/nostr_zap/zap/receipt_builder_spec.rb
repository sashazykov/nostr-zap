# frozen_string_literal: true

require 'spec_helper'

RSpec.describe NostrZap::Zap::ReceiptBuilder do
  subject(:builder) do
    described_class.new(
      zap_request_json: zap_request_json,
      bolt11_invoice: bolt11_invoice,
      key_pair: key_pair,
      paid_at: paid_at,
    )
  end

  let(:key_pair) { NostrZap::KeyPair.generate }
  let(:paid_at) { 1_700_000_000 }

  let :zap_request do
    pubkey = 'a' * 64
    tags = [
      ['p', 'recipient_pubkey_hex'],
      ['relays', 'wss://relay1.example.com', 'wss://relay2.example.com'],
      %w[amount 21000],
    ]
    {
      'id' => 'b' * 64,
      'pubkey' => pubkey,
      'created_at' => 1_609_459_200,
      'kind' => 9734,
      'tags' => tags,
      'content' => '',
      'sig' => 'c' * 128,
    }
  end

  let(:zap_request_json) { zap_request.to_json }
  let(:bolt11_invoice) { 'lnbc10n1pn9m2gtqpp8xav9...' }

  describe '#build' do
    let(:event) { builder.build }

    it 'returns a NostrZap::Event' do
      expect(event).to be_a(NostrZap::Event)
    end

    it 'sets kind to 9735' do
      expect(event.kind).to eq(9735)
    end

    it 'sets empty content' do
      expect(event.content).to eq('')
    end

    it 'sets created_at from paid_at' do
      expect(event.created_at).to eq(paid_at)
    end

    it 'sets pubkey to the key pair public key' do
      expect(event.pubkey).to eq(key_pair.public_key_hex)
    end

    it 'generates a valid event ID' do
      expect(event.id).to match(/\A[0-9a-f]{64}\z/)
      expect(event.id_valid?).to be(true)
    end

    it 'generates a valid signature' do
      expect(event.sig).to match(/\A[0-9a-f]{128}\z/)
      expect(event.signature_valid?).to be(true)
    end

    it 'includes bolt11 tag' do
      expect(event.tags).to include(['bolt11', bolt11_invoice])
    end

    it 'includes description tag with zap request JSON' do
      expect(event.tags).to include(['description', zap_request_json])
    end

    it 'includes p tag with recipient pubkey' do
      expect(event.tags).to include(%w[p recipient_pubkey_hex])
    end

    it 'includes P tag with sender pubkey' do
      expect(event.tags).to include(['P', 'a' * 64])
    end

    context 'when preimage is provided' do
      subject(:builder) do
        described_class.new(
          zap_request_json: zap_request_json,
          bolt11_invoice: bolt11_invoice,
          key_pair: key_pair,
          paid_at: paid_at,
          preimage: 'abc123',
        )
      end

      it 'includes preimage tag' do
        expect(event.tags).to include(%w[preimage abc123])
      end
    end

    context 'when preimage is not provided' do
      it 'does not include preimage tag' do
        expect(event.tags.map(&:first)).not_to include('preimage')
      end
    end

    context 'when zap request has e tag' do
      let :zap_request do
        super().tap { |zr| zr['tags'] << %w[e event_id_being_zapped] }
      end

      it 'includes e tag in receipt' do
        expect(event.tags).to include(%w[e event_id_being_zapped])
      end
    end

    context 'when zap request has a tag' do
      let :zap_request do
        super().tap { |zr| zr['tags'] << ['a', '30023:pubkey:identifier'] }
      end

      it 'includes a tag in receipt' do
        expect(event.tags).to include(['a', '30023:pubkey:identifier'])
      end
    end
  end

  describe '#relay_urls' do
    it 'returns relay URLs from the zap request' do
      expect(builder.relay_urls).to eq(%w[wss://relay1.example.com wss://relay2.example.com])
    end

    context 'when zap request has no relays tag' do
      let :zap_request do
        req = super()
        req['tags'] = req['tags'].reject { |tag| tag[0] == 'relays' }
        req
      end

      it 'returns empty array' do
        expect(builder.relay_urls).to eq([])
      end
    end
  end
end
