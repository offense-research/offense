class Offense < Formula
  desc "Security tools for coding agents: Offense hosted-service CLI"
  homepage "https://offense.sh"
  url "https://github.com/offense-research/offense/releases/download/cli-v0.2.0/offense-cli-0.2.0.tgz"
  sha256 "a2c475df0b69749d3abed5a425fe8a8e032865a9309cad64cc1984553740b1d1"
  license "Apache-2.0"
  revision 1

  livecheck do
    url "https://github.com/offense-research/offense/releases/latest"
    strategy :github_latest
    regex(/^cli-v(\d+\.\d+\.\d+)$/i)
  end

  depends_on "node"

  def install
    # Use the reviewed bundle, including its embedded third-party notices.
    # No npm lifecycle scripts, credentials or scanner engines are needed.
    libexec.install "dist/offense.mjs" => "offense"
    chmod 0755, libexec/"offense"
    (bin/"offense").write_env_script libexec/"offense", PATH: "#{formula_opt_bin("node")}:$PATH"
    pkgshare.install "LICENSE", "NOTICE", "THIRD_PARTY_LICENSES.txt"
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
