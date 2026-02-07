# frozen_string_literal: true

require 'spec_helper'

RSpec.describe NostrZap::RelayClient do
  describe '#publish_event' do
    it 'attempts to connect to all relays' do
      client = described_class.new(timeout: 1)
      allow(client).to receive(:publish_to_relay).and_return({ success: true, message: 'ok' })

      results = client.publish_event(
        event: { 'id' => 'abc' },
        relay_urls: ['wss://relay1.example.com', 'wss://relay2.example.com'],
      )

      expect(results.keys).to contain_exactly('wss://relay1.example.com', 'wss://relay2.example.com')
    end

    it 'handles connection failures' do
      client = described_class.new(timeout: 1)
      allow(client).to receive(:publish_to_relay)
        .and_return({ success: false, message: 'connection refused' })

      results = client.publish_event(event: { 'id' => 'abc' }, relay_urls: ['wss://relay.example.com'])
      expect(results['wss://relay.example.com'][:success]).to be(false)
    end
  end

  describe '#publish_to_relay' do
    it 'returns failure when DNS resolution fails' do
      allow(TCPSocket).to receive(:new).and_raise(SocketError, 'getaddrinfo: nodename nor servname provided')

      client = described_class.new
      result = client.publish_to_relay(event: { 'id' => 'abc' }, relay_url: 'wss://invalid.example.com')
      expect(result[:success]).to be(false)
    end

    it 'returns failure on timeout' do
      allow(TCPSocket).to receive(:new).and_raise(Errno::ETIMEDOUT)

      client = described_class.new
      result = client.publish_to_relay(event: { 'id' => 'abc' }, relay_url: 'wss://slow.example.com')
      expect(result[:success]).to be(false)
    end
  end

  describe 'OK response parsing' do
    let(:client) { described_class.new }

    it 'parses success response' do
      result = client.send(:parse_ok_response, '["OK","abc123",true,""]', 'abc123')
      expect(result).to eq({ success: true, message: 'Published' })
    end

    it 'parses failure response' do
      result = client.send(:parse_ok_response, '["OK","abc123",false,"duplicate:"]', 'abc123')
      expect(result).to eq({ success: false, message: 'duplicate:' })
    end

    it 'returns nil for non-matching event ID' do
      result = client.send(:parse_ok_response, '["OK","other",true,""]', 'abc123')
      expect(result).to be_nil
    end

    it 'returns nil for invalid JSON' do
      result = client.send(:parse_ok_response, 'not json', 'abc123')
      expect(result).to be_nil
    end
  end
end
