# frozen_string_literal: true

RSpec.describe 'gem autorequire compatibility' do
  it "supports require 'nostr-zap'" do
    expect { require 'nostr-zap' }.not_to raise_error
    expect(defined?(NostrZap)).to eq('constant')
  end
end
