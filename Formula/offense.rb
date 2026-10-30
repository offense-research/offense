class Offense < Formula
  desc "Security tools for coding agents: Offense hosted-service CLI"
  homepage "https://offense.sh"
  url "https://github.com/offense-research/offense/archive/6e979cda6d9ba46ac6d5291fc356ab53e22fc910.tar.gz"
  version "0.2.0"
  sha256 "ecde8cff431b480aea3b7173f3e67db8b430048009709d12e4cea042b8f455cf"
  license "Apache-2.0"

  livecheck do
    url "https://github.com/offense-research/offense/releases/latest"
    strategy :github_latest
    regex(/^cli-v(\d+\.\d+\.\d+)$/i)
  end

  depends_on "node"

  def install
    # Use the reviewed bundle, including its embedded third-party notices.
    # No npm lifecycle scripts, credentials or scanner engines are needed.
    libexec.install "public/skills/offense/scripts/cli.mjs" => "offense"
    chmod 0755, libexec/"offense"
    (bin/"offense").write_env_script libexec/"offense", PATH: "#{formula_opt_bin("node")}:$PATH"
    pkgshare.install "LICENSE", "NOTICE", "cli/THIRD_PARTY_LICENSES.txt"
  end

  test do
    ENV["OFFENSE_CONFIG_DIR"] = (testpath/"config").to_s
    ENV["OFFENSE_API_URL"] = "http://127.0.0.1:1"
    %w[OFFENSE_API_KEY PURPLE_SCAN_KEY].each { |key| ENV.delete(key) }
    assert_equal version.to_s, JSON.parse(shell_output("#{bin}/offense --version"))["version"]
    assert_includes JSON.parse(shell_output("#{bin}/offense --help"))["commands"], "login [--no-browser]"
    status = JSON.parse(shell_output("#{bin}/offense status"))
    assert_equal false, status["signedIn"]
    assert_equal "http://127.0.0.1:1", status["endpoint"]
    preview = JSON.parse(shell_output("#{bin}/offense k8s collect --context release-check --preview"))
    assert_equal "preview", preview["status"]
    assert_equal "release-check", preview.dig("scope", "context")
    assert_equal false, preview.dig("scope", "withNova")
    refute_path_exists testpath/"config"
  end
end
