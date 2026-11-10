# typed: false
# frozen_string_literal: true

class Agentshield < Formula
  desc "Deterministic, offline security scanner and runtime guard for AI agent tools & MCP servers"
  homepage "https://aiconnai.github.io/agentshield"
  version "1.0.3"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/aiconnai/agentshield/releases/download/v1.0.3/agentshield-v1.0.3-aarch64-apple-darwin.tar.gz"
      sha256 "REPLACE_WITH_V1_0_3_RELEASE_SHA256"
    else
      url "https://github.com/aiconnai/agentshield/releases/download/v1.0.3/agentshield-v1.0.3-x86_64-apple-darwin.tar.gz"
      sha256 "REPLACE_WITH_V1_0_3_RELEASE_SHA256"
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/aiconnai/agentshield/releases/download/v1.0.3/agentshield-v1.0.3-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "REPLACE_WITH_V1_0_3_RELEASE_SHA256"
    else
      url "https://github.com/aiconnai/agentshield/releases/download/v1.0.3/agentshield-v1.0.3-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "REPLACE_WITH_V1_0_3_RELEASE_SHA256"
    end
  end

  def install
    bin.install "agentshield"
  end

  test do
    assert_match "agentshield 1.0.3", shell_output("#{bin}/agentshield --version")
  end
end
