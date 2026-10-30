class Offense < Formula
  desc "Security tools for coding agents: Offense hosted-service CLI"
  homepage "https://offense.sh"
  url "https://github.com/offense-research/offense/archive/6e979cda6d9ba46ac6d5291fc356ab53e22fc910.tar.gz"
  version "0.2.0"
  sha256 "ecde8cff431b480aea3b7173f3e67db8b430048009709d12e4cea042b8f455cf"
  license "Apache-2.0"

  depends_on "node"

  def install
    # Use the reviewed bundle, including its embedded third-party notices.
    # No npm lifecycle scripts, credentials or scanner engines are needed.
    libexec.install "public/skills/offense/scripts/cli.mjs" => "offense"
    chmod 0755, libexec/"offense"
    (bin/"offense").write_env_script libexec/"offense", PATH: "#{Formula["node"].opt_bin}:$PATH"
    pkgshare.install "LICENSE", "NOTICE", "cli/THIRD_PARTY_LICENSES.txt"
  end

  test do
    assert_equal version.to_s, JSON.parse(shell_output("#{bin}/offense --version"))["version"]
    assert_includes JSON.parse(shell_output("#{bin}/offense --help"))["commands"], "login [--no-browser]"
  end
end
