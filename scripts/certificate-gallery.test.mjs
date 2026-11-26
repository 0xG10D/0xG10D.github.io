import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import sharp from 'sharp';
import { validateGallery } from './validate-certificates.mjs';

test('only audited local raster previews enter the gallery', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'certificate-test-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(join(root, 'public/images/certificates'), { recursive: true });
  const bytes = await sharp({ create: { width: 20, height: 10, channels: 3, background: '#fff' } }).webp().toBuffer();
  await writeFile(join(root, 'public/images/certificates/course.webp'), bytes);
  const entry = {
    id: 'course', title: 'Course completion', issuer: 'Example Academy', date: null,
    category: 'Training', image: '/images/certificates/course.webp', width: 20, height: 10,
    redacted: true, sha256: createHash('sha256').update(bytes).digest('hex')
  };
  assert.deepEqual(await validateGallery([entry], root), []);
  for (const patch of [
    { image: 'https://example.com/private.pdf' }, { image: '/images/certificates/../private.webp' },
    { image: '/images/certificates/missing.webp' }, { category: 'Verified' }, { issuer: '' },
    { title: 'user@example.com' }, { date: 'https://private.example/verify' },
    { id: '../private' }, { id: '990101101234' }, { width: 0 }, { height: 99 }, { redacted: 'yes' },
    { sha256: '0'.repeat(64) }, { sourceUrl: 'private' }
  ]) {
    assert.ok((await validateGallery([{ ...entry, ...patch }], root)).length > 0, JSON.stringify(patch));
  }
  assert.ok((await validateGallery([entry, entry], root)).some((e) => e.includes('duplicate')));
  assert.ok((await validateGallery({}, root)).length > 0);
  assert.ok((await validateGallery([], root)).length > 0);
  await writeFile(join(root, 'public/images/certificates/original.pdf'), 'private original');
  assert.ok((await validateGallery([entry], root)).some((e) => e.includes('unlisted')));
  await rm(join(root, 'public/images/certificates/original.pdf'));
  const invalidBytes = Buffer.from('not-a-WebP-raster');
  await writeFile(join(root, 'public/images/certificates/course.webp'), invalidBytes);
  assert.ok((await validateGallery([{ ...entry, sha256: createHash('sha256').update(invalidBytes).digest('hex') }], root)).some((e) => e.includes('non-WebP')));
  const appendedBytes = Buffer.concat([bytes, Buffer.from('synthetic private payload')]);
  await writeFile(join(root, 'public/images/certificates/course.webp'), appendedBytes);
  assert.ok((await validateGallery([{ ...entry, sha256: createHash('sha256').update(appendedBytes).digest('hex') }], root)).some((e) => e.includes('metadata')));
  const metadataBytes = await sharp(bytes).withMetadata().webp().toBuffer();
  await writeFile(join(root, 'public/images/certificates/course.webp'), metadataBytes);
  assert.ok((await validateGallery([{ ...entry, sha256: createHash('sha256').update(metadataBytes).digest('hex') }], root)).some((e) => e.includes('metadata')));
});
