# frozen_string_literal: true

require 'json'

module NostrZap
  module Zap
    # Validates NOSTR zap request events (kind 9734) according to NIP-57.
    #
    # A valid zap request must:
    # - Be a valid JSON string representing a NOSTR event
    # - Have kind = 9734
    # - Have a valid Schnorr signature (when verification is enabled)
    # - Have a 'p' tag with the recipient's pubkey
    # - Have a 'relays' tag with at least one safe relay URL
    #
    # @example
    #   validator = NostrZap::Zap::RequestValidator.new(json_string)
    #   if validator.valid?
    #     event = validator.parsed_event
    #     relays = validator.relay_urls
    #   else
    #     puts validator.errors
    #   end
    #
    class RequestValidator
      ZAP_REQUEST_KIND = 9734

      attr_reader :errors, :parsed_event

      # @param zap_request_json [String] JSON string of the zap request event
      # @param verify_signatures [Boolean] whether to verify BIP-340 signatures (default: true)
      def initialize(zap_request_json, verify_signatures: true)
        @zap_request_json = zap_request_json
        @verify_signatures = verify_signatures
        @errors = []
        @parsed_event = nil
      end

      # Validates the zap request and returns true if valid.
      #
      # @return [Boolean]
      def valid?
        @errors = []
        @parsed_event = nil
        !!(parse_json && structure_valid? && fields_format_valid? &&
          kind_valid? && tags_valid? && event_id_valid? && signature_valid?)
      end

      # @return [String, nil] recipient pubkey from the p tag
      def recipient_pubkey
        find_tag_value('p')
      end

      # @return [Array<String>] relay URLs from the relays tag
      def relay_urls
        return [] unless @parsed_event

        relays_tag = @parsed_event['tags']&.find { |tag| tag[0] == 'relays' }
        relays_tag&.slice(1..) || []
      end

      # @return [Integer, nil] amount in millisatoshis
      def amount_msats
        find_tag_value('amount')&.to_i
      end

      # @return [String, nil] event ID being zapped
      def zapped_event_id
        find_tag_value('e')
      end

      private

      def find_tag_value(tag_name)
        return nil unless @parsed_event

        tag = @parsed_event['tags']&.find { |t| t[0] == tag_name }
        tag&.dig(1)
      end

      def fail_with(message)
        @errors << message
        nil
      end

      def parse_json
        @parsed_event = JSON.parse(@zap_request_json)
        unless @parsed_event.is_a?(Hash)
          @parsed_event = nil
          return fail_with('Invalid event format')
        end
        true
      rescue JSON::ParserError => e
        fail_with("Invalid JSON: #{e.message}")
      end

      def structure_valid?
        missing_fields = %w[id pubkey created_at kind tags content sig] - @parsed_event.keys
        return true if missing_fields.empty?

        fail_with("Missing required fields: #{missing_fields.join(', ')}")
      end

      def fields_format_valid?
        { 'id' => 64, 'pubkey' => 64, 'sig' => 128 }.all? do |field, length|
          value = @parsed_event[field]
          if value.is_a?(String) && value.length == length && value.match?(/\A[0-9a-f]+\z/i)
            true
          else
            fail_with("Invalid '#{field}': expected #{length}-character hex string")
          end
        end
      end

      def kind_valid?
        kind = @parsed_event['kind']
        return true if kind.is_a?(Integer) && kind == ZAP_REQUEST_KIND

        fail_with("Invalid kind: expected integer #{ZAP_REQUEST_KIND}, got #{kind.inspect}")
      end

      def tags_valid?
        p_tag_valid? && relays_tag_valid?
      end

      def p_tag_valid?
        p_tag = @parsed_event['tags']&.find { |tag| tag[0] == 'p' }
        value = p_tag&.[](1)
        return fail_with("Missing required 'p' tag (recipient pubkey)") unless value.is_a?(String) && !value.empty?

        return true if value.is_a?(String) && value.match?(/\A[0-9a-f]{64}\z/i)

        fail_with("Invalid 'p' tag: expected 64-character hex pubkey")
      end

      def relays_tag_valid?
        relays_tag = @parsed_event['tags']&.find { |tag| tag[0] == 'relays' }
        urls = relays_tag&.slice(1..)&.compact
        return fail_with("Missing required 'relays' tag with at least one relay URL") if urls.nil? || urls.empty?

        urls.all? do |url|
          (error = RelayUrlValidator.validate(url)) ? fail_with(error) : true
        end
      end

      def event_id_valid?
        computed = Crypto.compute_event_id(
          pubkey: @parsed_event['pubkey'],
          created_at: @parsed_event['created_at'],
          kind: @parsed_event['kind'],
          tags: @parsed_event['tags'],
          content: @parsed_event['content']
        )
        return true if @parsed_event['id'] == computed

        fail_with('Event ID does not match computed hash')
      end

      def signature_valid?
        return true unless @verify_signatures

        valid = Crypto.verify_signature?(
          @parsed_event['id'],
          @parsed_event['pubkey'],
          @parsed_event['sig']
        )
        return true if valid

        fail_with('Invalid signature')
      rescue StandardError => e
        fail_with("Signature validation error: #{e.message}")
      end
    end
  end
end
