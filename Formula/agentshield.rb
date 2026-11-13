# typed: false
# frozen_string_literal: true

class Agentshield < Formula
  desc "Deterministic, offline security scanner and runtime guard for AI agent tools & MCP servers"
  homepage "https://aiconnai.github.io/agentshield"
  version "1.1.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/aiconnai/agentshield/releases/download/v1.1.0/agentshield-v1.1.0-aarch64-apple-darwin.tar.gz"
      sha256 "955c4938cdecd5df9a0540b92f7dfd7237272f77bcd925f7201f1211ce88091a"
    else
      url "https://github.com/aiconnai/agentshield/releases/download/v1.1.0/agentshield-v1.1.0-x86_64-apple-darwin.tar.gz"
      sha256 "4c27767daa49ec4a41bd3ee750847f82888a83119bf5cd857629d3b8de202c69"
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/aiconnai/agentshield/releases/download/v1.1.0/agentshield-v1.1.0-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "71e59f263b47540081308310b8bac87145a86eb38e7890354ff661ade18b877e"
    else
      url "https://github.com/aiconnai/agentshield/releases/download/v1.1.0/agentshield-v1.1.0-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "eeb26849e04f694e004ac2238f5620a2710941e554627e3a2c3a5be7823ca582"
    end
  end

  def install
    bin.install "agentshield"
  end

  test do
    assert_match "agentshield 1.1.0", shell_output("#{bin}/agentshield --version")
  end
end
