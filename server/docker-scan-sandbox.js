import { execFile } from 'node:child_process';

// Operator-selected local image only. Uploaded repositories never choose commands,
// mounts, images or network policy. Docker access is a privileged operator role.
export async function createDockerScanSandbox({ image = 'offense-source:local' } = {}) {
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._/:@-]*$/.test(image)) throw new Error('Invalid local scanner image.');
  const name = id => {
    if (!/^[a-f0-9]{32}$/.test(id)) throw new Error('Invalid scan ID.');
    return `offense-source-${id}`;
  };
  const docker = (args, options = {}) => new Promise((resolve, reject) => {
    execFile('docker', args, { timeout: 30_000, maxBuffer: 10 * 1024 * 1024, ...options }, (error, stdout) => {
      if (error) reject(new Error('Local scanner container operation failed.'));
      else resolve(stdout);
    });
  });
  const failed = () => ({ status: 'failed', tools: [], findings: [], error: 'Local scanner did not return a complete bounded report.' });
  // Do not advertise a configured source runtime when its local image is absent.
  await docker(['image', 'inspect', image]);
  return {
    tools: ['opengrep', 'zizmor'],
    async start(input) {
      const container = name(input.id);
      if (!Array.isArray(input.tools) || !input.tools.length || input.tools.some(tool => !['opengrep', 'zizmor'].includes(tool)) || input.artifact || input.assessment)
        throw new Error('The local source image supports only Opengrep and Zizmor text scans.');
      // A retry must inspect the same container, never execute a second job.
      try {
        await docker(['container', 'inspect', container]);
        return { status: 'running' };
      } catch { /* create below; a name collision fails closed */ }
      await docker(['create', '--name', container, '--network=none', '--read-only',
        '--cap-drop=ALL', '--security-opt=no-new-privileges', '--pids-limit=128',
        '--memory=2g', '--cpus=2', '--user=10002:10002',
        '--tmpfs=/tmp:rw,exec,nosuid,nodev,size=512m,mode=1777',
        '--log-driver=local', '--log-opt=max-size=10m', '--log-opt=max-file=1', '--log-opt=compress=false',
        '--interactive', '--entrypoint=sh', image, '-c',
        'timeout -s KILL 660 node /opt/purple/agent/scan-runner.mjs && cat /tmp/purple-scan-result.json']);
      const child = execFile('docker', ['start', '--attach', '--interactive', container],
        { timeout: 680_000, maxBuffer: 10 * 1024 * 1024 }, () => {});
      child.stdin.on('error', () => {});
      child.stdin.end(JSON.stringify(input));
      return { status: 'running' };
    },
    async get(id) {
      const container = name(id);
      const state = JSON.parse(await docker(['inspect', '--format={{json .State}}', container]));
      if (state.Running || state.Status === 'created') return { status: 'running' };
      if (state.Status !== 'exited' || state.ExitCode !== 0 || state.OOMKilled) return failed();
      try {
        const report = JSON.parse(await docker(['logs', container]));
        if (!['completed', 'partial', 'failed'].includes(report.status) || !Array.isArray(report.tools) || !Array.isArray(report.findings)) return failed();
        return report;
      } catch { return failed(); }
    },
    async destroy(id) {
      const container = name(id);
      if ((await docker(['container', 'ls', '--all', '--filter', `name=^/${container}$`, '--format={{.Names}}'])).trim())
        await docker(['rm', '--force', container]);
      return {};
    }
  };
}
