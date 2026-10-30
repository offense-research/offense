export function verificationCheck(check, originalRegression = false) {
  if (!check) return { label: 'not run', output: '' };
  const incomplete = check.protocolVersion === 2 && (!check.complete || check.summary?.skipped > 0 || check.summary?.todo > 0 || check.summary?.cancelled > 0);
  const infrastructure = check.classification === 'infrastructure_error' || check.infrastructureErrors?.length > 0;
  const passed = !incomplete && !infrastructure && ( typeof check.passed === 'boolean' ? check.passed : check.code === 0);
  const interrupted = check.timedOut || Boolean(check.signal) || ('code' in check && check.code === null) || /timed out|SIGKILL|SIGTERM/i.test(check.output || '');
  return {
    label: passed ? 'passed' : interrupted ? 'interrupted' : infrastructure ? 'setup / runtime error' : incomplete ? 'incomplete / skipped tests' : originalRegression && check.classification === 'security_assertion_failure' ? 'security assertion reproduced' : check.classification === 'infrastructure_error' ? 'setup / runtime error' : 'failed',
    output: check.output ?? [check.stdout, check.stderr].filter(Boolean).join('\n')
  };
}
