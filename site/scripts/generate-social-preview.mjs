// Regenerate with: OFFENSE_PLAYWRIGHT_PATH=/path/to/playwright/index.mjs node scripts/generate-social-preview.mjs
// Requires Playwright, a local Chromium browser, and ffmpeg on PATH. The site has no runtime dependency on these tools.
import { readFile, mkdir, mkdtemp, writeFile, copyFile, rm } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { resolve, join } from 'node:path';
import { tmpdir } from 'node:os';
import { spawn } from 'node:child_process';
import { once } from 'node:events';

const root = fileURLToPath(new URL('../', import.meta.url));
const output = resolve(root, 'public/social');
const { chromium } = await import(process.env.OFFENSE_PLAYWRIGHT_PATH || 'playwright');
const [archivo, mark] = await Promise.all([
  readFile(resolve(root, 'public/fonts/archivo-latin.woff2')),
  readFile(resolve(root, 'public/offense-mark.svg')),
]);
await mkdir(output, { recursive: true });
const temporary = await mkdtemp(join(tmpdir(), 'offense-social-'));
const browser = await chromium.launch({
  executablePath: process.env.OFFENSE_CHROME_PATH || '/usr/bin/google-chrome',
  headless: true,
  args: ['--no-sandbox'],
});

try {
  const page = await browser.newPage({ viewport: { width: 1200, height: 630 }, deviceScaleFactor: 1 });
  await page.setContent('<!doctype html><html><body style="margin:0"><canvas width="1200" height="630"></canvas></body></html>');
  const frame = await page.evaluate(async ({ archivo, mark }) => {
    const font = await new FontFace('Archivo', `url(data:font/woff2;base64,${archivo})`, { weight: '400 800' }).load();
    document.fonts.add(font);
    const logo = new Image();
    logo.src = `data:image/svg+xml;base64,${mark}`;
    await logo.decode();
    const canvas = document.querySelector('canvas');
    const ctx = canvas.getContext('2d');
    ctx.fillStyle = '#141414';
    ctx.fillRect(0, 0, 1200, 630);

    // Keep the complete brand lockup inside a centered 600px-wide safe area.
    const label = 'offense';
    const iconSize = 128;
    const gap = 32;
    ctx.font = '700 96px Archivo';
    ctx.textBaseline = 'alphabetic';
    const metrics = ctx.measureText(label);
    const width = iconSize + gap + metrics.width;
    if (width > 600) throw new Error('Brand lockup exceeds the centered safe area.');
    const left = (1200 - width) / 2;
    const middle = 630 / 2;
    ctx.drawImage(logo, left, middle - iconSize / 2, iconSize, iconSize);
    ctx.fillStyle = '#f5f5f5';
    const baseline = middle + (metrics.actualBoundingBoxAscent - metrics.actualBoundingBoxDescent) / 2;
    ctx.fillText(label, left + iconSize + gap, baseline);
    return canvas.toDataURL('image/png').split(',')[1];
  }, { archivo: archivo.toString('base64'), mark: mark.toString('base64') });

  await page.locator('canvas').screenshot({ path: resolve(output, 'offense-logo.jpg'), type: 'jpeg', quality: 95 });
  const framePath = join(temporary, 'logo.png');
  await writeFile(framePath, Buffer.from(frame, 'base64'));
  const encoder = spawn('ffmpeg', [
    '-hide_banner', '-loglevel', 'error', '-y',
    '-loop', '1', '-framerate', '24', '-i', framePath,
    '-t', '6', '-an', '-c:v', 'libx264', '-preset', 'medium', '-crf', '18',
    '-pix_fmt', 'yuv420p', '-movflags', '+faststart',
    resolve(output, 'offense-logo.mp4'),
  ], { stdio: ['ignore', 'ignore', 'pipe'] });
  let encoderError = '';
  encoder.stderr.on('data', chunk => { encoderError += chunk; });
  const [status] = await once(encoder, 'close');
  if (status !== 0) throw new Error(`ffmpeg failed: ${encoderError}`);

  // Preserve legacy share URLs with the same simplified brand artwork.
  await Promise.all([
    copyFile(resolve(output, 'offense-logo.jpg'), resolve(output, 'offense-preview.jpg')),
    copyFile(resolve(output, 'offense-logo.mp4'), resolve(output, 'offense-preview.mp4')),
  ]);
  console.log('Generated centered logo-only social assets at 1200x630; silent 6-second H.264 video and JPEG poster. Legacy preview assets contain identical bytes.');
} finally {
  await browser.close();
  await rm(temporary, { recursive: true, force: true });
}
