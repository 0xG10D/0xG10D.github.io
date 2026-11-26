import { readFile, readdir } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';
import sharp from 'sharp';

const fields = ['id', 'title', 'issuer', 'date', 'category', 'image', 'width', 'height', 'redacted', 'sha256'];
const categories = ['Credential', 'Training', 'CTF', 'Contribution', 'Participation'];
const privateText = /https?:|@|\b\d{6}[- ]?\d{2}[- ]?\d{4}\b/i;

function isBareRaster(bytes) {
  if (bytes.length < 20 || bytes.toString('ascii', 0, 4) !== 'RIFF' || bytes.toString('ascii', 8, 12) !== 'WEBP') return false;
  if (bytes.readUInt32LE(4) !== bytes.length - 8) return false;
  const chunk = bytes.toString('ascii', 12, 16);
  const size = bytes.readUInt32LE(16);
  return ['VP8 ', 'VP8L'].includes(chunk) && size > 0 && 20 + size + (size % 2) === bytes.length;
}

export async function validateGallery(entries, root) {
  if (!Array.isArray(entries) || entries.length === 0) return ['gallery must contain audited entries'];
  const errors = [];
  const ids = new Set();
  const images = new Set();
  for (const [index, entry] of entries.entries()) {
    const label = `certificate ${index + 1}`;
    if (!entry || typeof entry !== 'object' || fields.some((key) => !(key in entry)) || Object.keys(entry).some((key) => !fields.includes(key))) {
      errors.push(`${label}: unexpected or missing fields`);
      continue;
    }
    if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(entry.id) || privateText.test(entry.id) || ids.has(entry.id)) errors.push(`${label}: invalid or duplicate id`);
    ids.add(entry.id);
    if (!categories.includes(entry.category)) errors.push(`${label}: invalid category`);
    for (const field of ['title', 'issuer']) {
      if (typeof entry[field] !== 'string' || !entry[field].trim() || privateText.test(entry[field])) errors.push(`${label}: invalid ${field}`);
    }
    if (entry.date !== null && (typeof entry.date !== 'string' || !entry.date.trim() || privateText.test(entry.date))) errors.push(`${label}: invalid date`);
    if (typeof entry.redacted !== 'boolean' || !/^[a-f0-9]{64}$/.test(entry.sha256)) errors.push(`${label}: missing audit fingerprint`);
    if (!Number.isInteger(entry.width) || entry.width < 1 || !Number.isInteger(entry.height) || entry.height < 1) errors.push(`${label}: invalid dimensions`);
    if (typeof entry.image !== 'string' || !/^\/images\/certificates\/[a-z0-9-]+\.webp$/.test(entry.image) || privateText.test(entry.image) || images.has(entry.image)) {
      errors.push(`${label}: invalid or duplicate preview path`);
      continue;
    }
    images.add(entry.image);
    try {
      const bytes = await readFile(join(root, 'public', entry.image));
      if (!isBareRaster(bytes)) {
        errors.push(`${label}: metadata, extra payload or non-WebP raster`);
        continue;
      }
      const metadata = await sharp(bytes).metadata();
      if (metadata.hasAlpha || (metadata.pages ?? 1) > 1) errors.push(`${label}: metadata, extra payload or non-opaque raster`);
      if (metadata.format !== 'webp' || metadata.width !== entry.width || metadata.height !== entry.height) errors.push(`${label}: raster dimensions or format mismatch`);
      if (metadata.exif || metadata.icc || metadata.iptc || metadata.xmp || metadata.comments?.length) errors.push(`${label}: embedded metadata`);
      if (createHash('sha256').update(bytes).digest('hex') !== entry.sha256) errors.push(`${label}: preview differs from audited fingerprint`);
    } catch {
      errors.push(`${label}: missing or unreadable raster`);
    }
  }
  try {
    for (const name of await readdir(join(root, 'public/images/certificates'))) {
      if (!images.has(`/images/certificates/${name}`)) errors.push('unlisted certificate asset in public directory');
    }
  } catch {
    errors.push('certificate asset directory missing');
  }
  return errors;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const root = dirname(dirname(fileURLToPath(import.meta.url)));
  const entries = JSON.parse(await readFile(join(root, 'src/content/achievements/certificate-gallery.json'), 'utf8'));
  const errors = await validateGallery(entries, root);
  if (errors.length) {
    console.error(errors.join('\n'));
    process.exitCode = 1;
  } else {
    console.log(`Certificate validation passed: ${entries.length} audited raster previews.`);
  }
}
