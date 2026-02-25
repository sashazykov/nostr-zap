# frozen_string_literal: true

require 'spec_helper'

RSpec.describe NostrZap::RelayUrlValidator do
  describe '.validate' do
    subject(:error) { described_class.validate(url) }

    before do
      allow(Resolv).to receive(:getaddresses).and_return(['93.184.215.14'])
    end

    context 'with a valid wss:// relay URL' do
      let(:url) { 'wss://relay.example.com' }

      it { is_expected.to be_nil }
    end

    context 'with ws:// scheme' do
      let(:url) { 'ws://relay.example.com' }

      it { is_expected.to be_nil }
    end

    context 'with non-websocket scheme' do
      let(:url) { 'http://relay.example.com' }

      it { is_expected.to match(/only ws or wss is allowed/) }
    end

    context 'with missing host' do
      let(:url) { 'wss://' }

      it { is_expected.to match(/missing host/) }
    end

    context 'with localhost' do
      let(:url) { 'wss://localhost' }

      before { allow(Resolv).to receive(:getaddresses).with('localhost').and_return(['127.0.0.1']) }

      it { is_expected.to match(%r{private/reserved address}) }
    end

    context 'with localhost and private checks disabled' do
      let(:url) { 'ws://localhost:4848' }

      before { allow(Resolv).to receive(:getaddresses).with('localhost').and_return(['127.0.0.1']) }

      it 'accepts the URL' do
        expect(described_class.validate(url, check_private: false)).to be_nil
      end
    end

    context 'with private 10.x range' do
      let(:url) { 'wss://internal.example.com' }

      before { allow(Resolv).to receive(:getaddresses).with('internal.example.com').and_return(['10.0.0.1']) }

      it { is_expected.to match(%r{private/reserved address}) }
    end

    context 'with private 192.168.x range' do
      let(:url) { 'wss://internal.example.com' }

      before { allow(Resolv).to receive(:getaddresses).with('internal.example.com').and_return(['192.168.1.1']) }

      it { is_expected.to match(%r{private/reserved address}) }
    end

    context 'with link-local range' do
      let(:url) { 'wss://link-local.example.com' }

      before { allow(Resolv).to receive(:getaddresses).with('link-local.example.com').and_return(['169.254.1.1']) }

      it { is_expected.to match(%r{private/reserved address}) }
    end

    context 'with IPv6 loopback' do
      let(:url) { 'wss://ipv6.example.com' }

      before { allow(Resolv).to receive(:getaddresses).with('ipv6.example.com').and_return(['::1']) }

      it { is_expected.to match(%r{private/reserved address}) }
    end

    context 'when DNS resolution fails' do
      let(:url) { 'wss://unresolvable.example.com' }

      before do
        allow(Resolv).to receive(:getaddresses).with('unresolvable.example.com').and_raise(Resolv::ResolvError)
      end

      it { is_expected.to be_nil }
    end

    context 'when DNS returns no addresses' do
      let(:url) { 'wss://no-records.example.com' }

      before { allow(Resolv).to receive(:getaddresses).with('no-records.example.com').and_return([]) }

      it { is_expected.to be_nil }
    end

    context 'when relay host does not resolve but is not a literal private IP' do
      let(:url) { 'wss://relay.nostr.bg' }

      before { allow(Resolv).to receive(:getaddresses).with('relay.nostr.bg').and_return([]) }

      it { is_expected.to be_nil }
    end

    context 'with a malformed URI' do
      let(:url) { '://not valid' }

      it { is_expected.to match(/Invalid relay URL/) }
    end
  end
end
