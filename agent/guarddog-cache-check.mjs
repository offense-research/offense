import { guardDogCachesFresh } from './scan-additional-adapters.mjs';

const directory = process.argv[2];
if (!directory || !(await guardDogCachesFresh(directory))) {
  process.stderr.write('GuardDog package-popularity cache is absent or stale.\n');
  process.exitCode = 1;
} else {
  process.stdout.write('GuardDog package-popularity cache is ready for offline scanning.\n');
}
