# frozen_string_literal: true

require_relative 'lib/nostr_zap/version'

Gem::Specification.new do |spec|
  spec.name = 'nostr-zap'
  spec.version = NostrZap::VERSION
  spec.authors = ['Alexander Zykov']
  spec.email = ['alexandrz@gmail.com']

  spec.summary = 'NIP-57 Zaps for NOSTR — validate zap requests, build zap receipts, publish to relays'
  spec.description = 'A Ruby toolkit for NOSTR NIP-57 Lightning Zaps. Includes BIP-340 key management, ' \
                     'event signing/verification, zap request validation, zap receipt construction, ' \
                     'relay publishing via WebSocket, and SSRF-safe relay URL validation. ' \
                     'No Rails dependency required.'
  spec.homepage = 'https://github.com/sashazykov/nostr-zap'
  spec.license = 'MIT'
  spec.required_ruby_version = '>= 3.1.0'

  spec.metadata['homepage_uri'] = spec.homepage
  spec.metadata['source_code_uri'] = spec.homepage
  spec.metadata['changelog_uri'] = "#{spec.homepage}/blob/main/CHANGELOG.md"
  spec.metadata['rubygems_mfa_required'] = 'true'

  spec.files = Dir['lib/**/*.rb', 'LICENSE', 'README.md']
  spec.require_paths = ['lib']

  spec.add_dependency 'bip-schnorr', '~> 0.7'
  spec.add_dependency 'websocket', '~> 1.0'
end
