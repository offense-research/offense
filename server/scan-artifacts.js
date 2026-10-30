export const ARTIFACT_LIMITS = Object.freeze({
  'image-tar': 80 * 1024 * 1024,
  'git-bundle': 32 * 1024 * 1024,
  'package-archive': 16 * 1024 * 1024,
  'cosign-save': 32 * 1024 * 1024,
  'web-har': 2 * 1024 * 1024,
  'mobile-app': 80 * 1024 * 1024
});

export const ARTIFACT_TOOLS = Object.freeze({
  'image-tar': ['trivy-image'],
  'git-bundle': ['gitleaks-history'],
  'package-archive': ['guarddog-npm', 'guarddog-pypi'],
  'cosign-save': ['cosign-image'],
  'web-har': ['zap-passive-har'],
  'mobile-app': ['mobsf-static']
});

export function artifactHeaders(request) {
  const kind = request.headers.get('x-purple-artifact-kind');
  const length = Number(request.headers.get('content-length'));
  const sha256 = request.headers.get('x-content-sha256') || '';
  if (!Object.hasOwn(ARTIFACT_LIMITS, kind)) throw new Error('Unsupported artifact kind.');
  if (!Number.isSafeInteger(length) || length < 1 || length > ARTIFACT_LIMITS[kind])
    throw new Error(`Artifact size must be between 1 and ${ARTIFACT_LIMITS[kind]} bytes.`);
  if (!/^[a-f0-9]{64}$/.test(sha256)) throw new Error('Send the lowercase SHA-256 artifact checksum.');
  if (request.headers.get('content-type')?.split(';')[0]?.trim() !== 'application/octet-stream')
    throw new Error('Use application/octet-stream for artifact uploads.');
  return { kind, size: length, sha256 };
}

export function limitArtifactStream(stream, expectedSize) {
  let bytes = 0;
  return stream.pipeThrough(new TransformStream({
    transform(chunk, controller) {
      if (!(chunk instanceof Uint8Array) || (bytes += chunk.byteLength) > expectedSize)
        throw new Error('Artifact body exceeds the declared size.');
      controller.enqueue(chunk);
    },
    flush() { if (bytes !== expectedSize) throw new Error('Artifact body is shorter than declared.'); }
  }));
}
