# frozen_string_literal: true

require 'socket'
require 'websocket'
require 'openssl'
require 'uri'
require 'json'
require 'concurrent'

module NostrZap
  # Client for publishing NOSTR events to relay servers via WebSocket.
  #
  # NOSTR relays accept events via WebSocket with the NIP-01 protocol:
  # - Send: ["EVENT", <event JSON>]
  # - Receive: ["OK", <event_id>, <success>, <message>]
  #
  # Supports publishing to multiple relays concurrently.
  #
  # @example
  #   client = NostrZap::RelayClient.new
  #   results = client.publish_event(
  #     event: event.to_h,
  #     relay_urls: ['wss://relay.example.com']
  #   )
  #   # => { 'wss://relay.example.com' => { success: true, message: 'saved' } }
  #
  class RelayClient
    DEFAULT_TIMEOUT_SECONDS = 10
    READ_TIMEOUT_SECONDS = 5

    class PublishError < Error; end

    # @param timeout [Integer] connection timeout in seconds
    # @param logger [#error, #warn, #info, nil] optional logger for error reporting
    def initialize(timeout: DEFAULT_TIMEOUT_SECONDS, logger: nil)
      @timeout = timeout
      @logger = logger
    end

    # Publishes an event to multiple relays.
    #
    # @param event [Hash] The signed NOSTR event to publish
    # @param relay_urls [Array<String>] List of relay WebSocket URLs
    # @return [Hash] Map of relay URL to result { success: bool, message: String }
    def publish_event(event:, relay_urls:)
      futures = relay_urls.to_h do |relay_url|
        future = Concurrent::Promises.future do
          publish_to_relay(event: event, relay_url: relay_url)
        end
        [relay_url, future]
      end

      futures.transform_values do |future|
        future.value(@timeout) || { success: false, message: 'Connection timeout' }
      end
    end

    # Publishes an event to a single relay.
    #
    # @param event [Hash] The signed NOSTR event to publish
    # @param relay_url [String] The relay WebSocket URL
    # @return [Hash] Result { success: bool, message: String }
    def publish_to_relay(event:, relay_url:)
      event_id = event[:id] || event['id']
      uri = URI.parse(relay_url)

      socket = create_socket(uri)
      perform_handshake(socket, uri)
      send_event(socket, event)
      wait_for_ok_response(socket, event_id)
    rescue => e
      @logger&.error("NostrZap::RelayClient error for #{relay_url}: #{e.message}")
      { success: false, message: e.message }
    ensure
      socket&.close
    end

  private

    def create_socket(uri)
      tcp_socket = TCPSocket.new(uri.host, uri.port || ((uri.scheme == 'wss') ? 443 : 80))

      if uri.scheme == 'wss'
        ssl_context = OpenSSL::SSL::SSLContext.new
        ssl_context.set_params
        ssl_socket = OpenSSL::SSL::SSLSocket.new(tcp_socket, ssl_context)
        ssl_socket.sync_close = true
        ssl_socket.hostname = uri.host
        ssl_socket.connect
        ssl_socket
      else
        tcp_socket
      end
    end

    def perform_handshake(socket, uri)
      handshake = WebSocket::Handshake::Client.new(url: uri.to_s)
      socket.write(handshake.to_s)

      deadline = current_time + READ_TIMEOUT_SECONDS
      until handshake.finished?
        remaining = deadline - current_time
        raise PublishError, 'WebSocket handshake timeout' unless remaining.positive?

        ready = socket_ready?(socket, [remaining, 0.5].min)
        raise PublishError, 'WebSocket handshake timeout' unless ready

        chunk = socket.read_nonblock(1024)
        handshake << chunk
      end

      raise PublishError, 'WebSocket handshake failed' unless handshake.valid?
    rescue IO::WaitReadable
      retry if current_time < deadline
      raise PublishError, 'WebSocket handshake timeout'
    rescue EOFError
      raise PublishError, 'Connection closed during WebSocket handshake'
    end

    def send_event(socket, event)
      message = ['EVENT', event].to_json
      frame = WebSocket::Frame::Outgoing::Client.new(version: 13, data: message, type: :text)
      socket.write(frame.to_s)
    end

    def wait_for_ok_response(socket, expected_event_id)
      frame_parser = WebSocket::Frame::Incoming::Client.new(version: 13)
      deadline = current_time + READ_TIMEOUT_SECONDS

      while current_time < deadline
        begin
          ready = socket_ready?(socket, 0.5)
          next unless ready

          data = socket.read_nonblock(4096)
          frame_parser << data

          while (frame = frame_parser.next)
            next unless frame.type == :text

            result = parse_ok_response(frame.data, expected_event_id)
            return result if result
          end
        rescue IO::WaitReadable
          next
        rescue EOFError
          break
        end
      end

      { success: false, message: 'Response timeout' }
    end

    def socket_ready?(socket, timeout)
      if socket.respond_to?(:wait_readable)
        socket.wait_readable(timeout)
      else
        IO.select([socket], nil, nil, timeout)
      end
    end

    def parse_ok_response(data, expected_event_id)
      parsed = JSON.parse(data)

      return nil unless parsed[0] == 'OK' && parsed[1] == expected_event_id

      relay_message = parsed[3]
      default_message = parsed[2] ? 'Published' : 'Rejected'

      {
        success: parsed[2] == true,
        message: (relay_message.nil? || relay_message.empty?) ? default_message : relay_message,
      }
    rescue JSON::ParserError
      nil
    end

    def current_time
      Process.clock_gettime(Process::CLOCK_MONOTONIC)
    end
  end
end
