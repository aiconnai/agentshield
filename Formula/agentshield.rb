# typed: false
# frozen_string_literal: true

class Agentshield < Formula
  desc "Deterministic, offline security scanner and runtime guard for AI agent tools & MCP servers"
  homepage "https://aiconnai.github.io/agentshield"
  version "1.0.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/aiconnai/agentshield/releases/download/v1.0.0/agentshield-v1.0.0-aarch64-apple-darwin.tar.gz"
      sha256 "3f88fd594fe603337506860af231b375b9e818ba5b3d33b6d4407a46500a02d2"
    else
      url "https://github.com/aiconnai/agentshield/releases/download/v1.0.0/agentshield-v1.0.0-x86_64-apple-darwin.tar.gz"
      sha256 "f34698e2da88926470f2d20bfc31763dc96a440f2784bf0f99dce34a3a2ad153"
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/aiconnai/agentshield/releases/download/v1.0.0/agentshield-v1.0.0-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "73eac2bac128234350c48e639f4475dc750d8c4f414b41e431aa1ce235d07951"
    else
      url "https://github.com/aiconnai/agentshield/releases/download/v1.0.0/agentshield-v1.0.0-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "897b28d970091517e1373c173da9810a2a8a5f376c78cb9e7772a0bcf70afef3"
    end
  end

  def install
    bin.install "agentshield"
  end

  test do
    assert_match "agentshield 1.0.0", shell_output("#{bin}/agentshield --version")
  end
end
