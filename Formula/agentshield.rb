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
      sha256 "515857349b77f35c40e137cbb3ee2aa0ac258e8b43b42b05de5b5f8efad8b525"
    else
      url "https://github.com/aiconnai/agentshield/releases/download/v1.0.3/agentshield-v1.0.3-x86_64-apple-darwin.tar.gz"
      sha256 "d09251fabe8894dc6964ce26538e7608717659a49836679b13bb775d98f5350e"
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/aiconnai/agentshield/releases/download/v1.0.3/agentshield-v1.0.3-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "84cf45d1b149f3b4d6121c60d6ae9cf57bfebf8749ed2bf5ed878e412b920bd9"
    else
      url "https://github.com/aiconnai/agentshield/releases/download/v1.0.3/agentshield-v1.0.3-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "4cccbeba132bfcd8ddea2dffd002474cf20779687040d9840d40ba44fae9c9ed"
    end
  end

  def install
    bin.install "agentshield"
  end

  test do
    assert_match "agentshield 1.0.3", shell_output("#{bin}/agentshield --version")
  end
end
