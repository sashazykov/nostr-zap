# frozen_string_literal: true

module NostrZap
  class Error < StandardError; end
  class ConfigurationError < Error; end
  class InvalidKeyError < Error; end
  class SigningError < Error; end
end

require_relative 'nostr_zap/version'
require_relative 'nostr_zap/crypto'
require_relative 'nostr_zap/key_pair'
require_relative 'nostr_zap/event'
require_relative 'nostr_zap/relay_url_validator'
require_relative 'nostr_zap/relay_client'
require_relative 'nostr_zap/zap/request_validator'
require_relative 'nostr_zap/zap/receipt_builder'
