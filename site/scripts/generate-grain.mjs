import { mkdir, writeFile } from 'node:fs/promises';
import { deflateSync } from 'node:zlib';

// Generate a repeatable monochrome tile once, rather than filtering every frame.
const size = 160;
let seed = 112358;
const pixels = Buffer.alloc((size + 1) * size);
for (let y = 0; y < size; y++) {
  const row = y * (size + 1);
  pixels[row] = 0;
  for (let x = 0; x < size; x++) {
    seed ^= seed << 13;
    seed ^= seed >>> 17;
    seed ^= seed << 5;
    pixels[row + x + 1] = seed & 255;
  }
}

function chunk(type, data) {
  const name = Buffer.from(type);
  const checksumInput = Buffer.concat([name, data]);
  let crc = 0xffffffff;
  for (const byte of checksumInput) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
  }
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length);
  const checksum = Buffer.alloc(4);
  checksum.writeUInt32BE((crc ^ 0xffffffff) >>> 0);
  return Buffer.concat([length, name, data, checksum]);
}

const header = Buffer.alloc(13);
header.writeUInt32BE(size, 0);
header.writeUInt32BE(size, 4);
header[8] = 8; // Eight-bit grayscale PNG.
const png = Buffer.concat([
  Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]),
  chunk('IHDR', header),
  chunk('IDAT', deflateSync(pixels)),
  chunk('IEND', Buffer.alloc(0)),
]);
const directory = new URL('../public/textures/', import.meta.url);
await mkdir(directory, { recursive: true });
await writeFile(new URL('grain.png', directory), png);
console.log(`Generated ${size}x${size} static grain tile (${png.length} bytes).`);
