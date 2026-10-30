// Trusted Node preload: test files execute only after this identity switch.
// This file is shipped in the read-only image, never read from the repository.
if (process.platform !== 'linux' || process.getuid?.() !== 0 ||
    process.env.PURPLE_FIX_OBSERVER_ISOLATION !== '1') {
  throw new Error('The isolated test observer requires its trusted Linux controller.');
}
process.setgroups([]);
process.setgid(1001);
process.setuid(1001);
if (process.getuid() !== 1001 || process.getgid() !== 1001 || process.getgroups().includes(0)) {
  throw new Error('Repository test privilege separation failed.');
}
delete process.env.PURPLE_FIX_OBSERVER_ISOLATION;
