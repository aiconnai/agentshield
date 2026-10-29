# typed: false
# frozen_string_literal: true

class Agentshield < Formula
  desc "Deterministic, offline security scanner and runtime guard for AI agent tools & MCP servers"
  homepage "https://aiconnai.github.io/agentshield"
  version "1.0.2"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/aiconnai/agentshield/releases/download/v1.0.2/agentshield-v1.0.2-aarch64-apple-darwin.tar.gz"
      sha256 "4da7ca623c2f61692c7037796c1ab31b822a7d2c84a2ba4857719c37cf82b530"
    else
      url "https://github.com/aiconnai/agentshield/releases/download/v1.0.2/agentshield-v1.0.2-x86_64-apple-darwin.tar.gz"
      sha256 "9ce170fd1cb05f99d5d1e850533950fb6c617375189dda6e2b31a47ff0894e26"
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/aiconnai/agentshield/releases/download/v1.0.2/agentshield-v1.0.2-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "4c57f4acd115f858c644903d10d2528fed9ac9f6da1c30a9feb152da1d684331"
    else
      url "https://github.com/aiconnai/agentshield/releases/download/v1.0.2/agentshield-v1.0.2-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "d56ebf3056a59cd349f7f03e817c0ce919f32a44eff21d2fe13d97bba2ae7b40"
    end
  end

  def install
    bin.install "agentshield"
  end

  test do
    assert_match "agentshield 1.0.2", shell_output("#{bin}/agentshield --version")
  end
end
