# frozen_string_literal: true

require 'ipaddr'
require 'resolv'
require 'uri'

module NostrZap
  # Validates relay URLs for zap flows.
  #
  # By default, accepts ws:// and wss:// schemes and blocks private/reserved
  # hosts to prevent SSRF. Private host checks can be disabled when validating
  # relay tags in incoming zap requests.
  #
  # Returns nil if valid, or an error message string if invalid.
  #
  # @example
  #   error = NostrZap::RelayUrlValidator.validate('wss://relay.example.com')
  #   error # => nil (valid)
  #
  #   error = NostrZap::RelayUrlValidator.validate('ws://localhost')
  #   error # => "Relay URL points to a private/reserved address: ws://localhost"
  #
  class RelayUrlValidator
    PRIVATE_IP_RANGES = [
      IPAddr.new('127.0.0.0/8'),
      IPAddr.new('10.0.0.0/8'),
      IPAddr.new('172.16.0.0/12'),
      IPAddr.new('192.168.0.0/16'),
      IPAddr.new('169.254.0.0/16'),
      IPAddr.new('0.0.0.0/8'),
      IPAddr.new('::1/128'),
      IPAddr.new('fc00::/7'),
      IPAddr.new('fe80::/10')
    ].freeze

    def self.validate(url, check_private: true)
      new(url, check_private: check_private).validate
    end

    def initialize(url, check_private: true)
      @url = url
      @check_private = check_private
    end

    def validate
      uri = URI.parse(@url)

      validate_scheme(uri) || validate_host(uri) || validate_not_private(uri)
    rescue URI::InvalidURIError
      "Invalid relay URL: #{@url}"
    end

    private

    attr_reader :check_private

    def validate_scheme(uri)
      return if %w[ws wss].include?(uri.scheme)

      "Invalid relay URL scheme '#{uri.scheme}' (only ws or wss is allowed): #{@url}"
    end

    def validate_host(uri)
      return if uri.host && !uri.host.empty?

      "Invalid relay URL (missing host): #{@url}"
    end

    def validate_not_private(uri)
      return unless check_private
      return unless private_host?(uri.host)

      "Relay URL points to a private/reserved address: #{@url}"
    end

    def private_host?(host)
      ip = parse_ip_literal(host)
      return private_ip?(ip) if ip

      addresses = Resolv.getaddresses(host)
      return false if addresses.empty?

      addresses.any? { |addr| private_ip?(addr) }
    rescue Resolv::ResolvError
      false
    end

    def parse_ip_literal(host)
      IPAddr.new(host)
    rescue IPAddr::InvalidAddressError
      nil
    end

    def private_ip?(ip)
      PRIVATE_IP_RANGES.any? { |range| range.include?(ip) }
    end
  end
end
