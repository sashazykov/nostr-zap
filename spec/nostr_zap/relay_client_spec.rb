# frozen_string_literal: true

require 'spec_helper'

RSpec.describe NostrZap::RelayClient do
  describe '#publish_event' do
    it 'attempts to connect to all relays' do
      client = described_class.new(timeout: 1)
      allow(client).to receive(:publish_to_relay).and_return({ success: true, message: 'ok' })

      results = client.publish_event(
        event: { 'id' => 'abc' },
        relay_urls: ['wss://relay1.example.com', 'wss://relay2.example.com']
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

    it 'cancels timed-out relay threads' do
      client = described_class.new(timeout: 1)
      timeout_thread = instance_double(Thread)
      success_thread = instance_double(Thread)

      allow(Thread).to receive(:new).and_return(timeout_thread, success_thread)
      allow(timeout_thread).to receive(:join).with(1).and_return(nil)
      allow(success_thread).to receive(:join).with(1).and_return(success_thread)
      allow(success_thread).to receive(:value).and_return({ success: true, message: 'ok' })
      expect(timeout_thread).to receive(:kill)

      results = client.publish_event(
        event: { 'id' => 'abc' },
        relay_urls: ['wss://relay1.example.com', 'wss://relay2.example.com']
      )

      expect(results['wss://relay1.example.com']).to eq({ success: false, message: 'Connection timeout' })
      expect(results['wss://relay2.example.com']).to eq({ success: true, message: 'ok' })
    end
  end

  describe '#publish_to_relay' do
    it 'returns failure when DNS resolution fails' do
      client = described_class.new
      allow(client).to receive(:resolve_connect_hosts).and_return(['93.184.215.14'])
      allow(TCPSocket).to receive(:new).and_raise(SocketError, 'getaddrinfo: nodename nor servname provided')

      result = client.publish_to_relay(event: { 'id' => 'abc' }, relay_url: 'wss://invalid.example.com')
      expect(result[:success]).to be(false)
    end

    it 'returns failure on timeout' do
      client = described_class.new
      allow(client).to receive(:resolve_connect_hosts).and_return(['93.184.215.14'])
      allow(TCPSocket).to receive(:new).and_raise(Errno::ETIMEDOUT)

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

  describe 'socket connection safety' do
    let(:client) { described_class.new }
    let(:uri) { URI.parse('wss://relay.example.com') }

    it 'connects to a resolved public IP instead of hostname' do
      tcp_socket = instance_double(TCPSocket)
      ssl_context = instance_double(OpenSSL::SSL::SSLContext, set_params: true)
      ssl_socket = instance_double(OpenSSL::SSL::SSLSocket, connect: true)
      allow(ssl_socket).to receive(:sync_close=)
      allow(ssl_socket).to receive(:hostname=)

      allow(Resolv).to receive(:getaddresses).with('relay.example.com').and_return(['93.184.215.14'])
      allow(OpenSSL::SSL::SSLContext).to receive(:new).and_return(ssl_context)
      allow(TCPSocket).to receive(:new).with('93.184.215.14', 443).and_return(tcp_socket)
      allow(OpenSSL::SSL::SSLSocket).to receive(:new).with(tcp_socket, ssl_context).and_return(ssl_socket)

      client.send(:create_socket, uri)

      expect(TCPSocket).to have_received(:new).with('93.184.215.14', 443)
      expect(ssl_socket).to have_received(:hostname=).with('relay.example.com')
    end

    it 'rejects hosts that only resolve to private addresses' do
      allow(Resolv).to receive(:getaddresses).with('relay.example.com').and_return(['192.168.1.1'])

      expect { client.send(:create_socket, uri) }
        .to raise_error(NostrZap::RelayClient::PublishError, %r{private/reserved})
    end

    it 'falls back to another resolved public IP when first fails' do
      tcp_socket = instance_double(TCPSocket)
      ssl_context = instance_double(OpenSSL::SSL::SSLContext, set_params: true)
      ssl_socket = instance_double(OpenSSL::SSL::SSLSocket, connect: true)
      allow(ssl_socket).to receive(:sync_close=)
      allow(ssl_socket).to receive(:hostname=)

      allow(Resolv).to receive(:getaddresses).with('relay.example.com').and_return(['2001:db8::1', '93.184.215.14'])
      allow(TCPSocket).to receive(:new).with('2001:db8::1', 443).and_raise(Errno::EHOSTUNREACH)
      allow(TCPSocket).to receive(:new).with('93.184.215.14', 443).and_return(tcp_socket)
      allow(OpenSSL::SSL::SSLContext).to receive(:new).and_return(ssl_context)
      allow(OpenSSL::SSL::SSLSocket).to receive(:new).with(tcp_socket, ssl_context).and_return(ssl_socket)

      client.send(:create_socket, uri)

      expect(TCPSocket).to have_received(:new).with('2001:db8::1', 443)
      expect(TCPSocket).to have_received(:new).with('93.184.215.14', 443)
    end
  end
end
