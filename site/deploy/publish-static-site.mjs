// Call inside the Cloudflare plugin executor after the scoped asset transfer.
// The completion token stays in executor memory and is never returned.
export default async function publishStaticSite(cloudflare, accountId, site, completionToken) {
  const base = `/accounts/${accountId}/workers/scripts/${site.name}`;
  const metadata = {
    main_module: 'fallback.js',
    compatibility_date: site.compatibilityDate,
    observability: site.observability,
    bindings: (site.services || []).map(({ binding, service, environment }) => ({
      type: 'service',
      name: binding,
      service,
      ...(environment === undefined ? {} : { environment }),
    })),
    assets: { jwt: completionToken, config: site.assetConfig },
    annotations: { 'workers/message': 'Publish the canonical Offense landing, setup and security tool catalog.' },
  };
  const boundary = 'OffenseStaticSite' + Date.now();
  const body = [
    `--${boundary}`,
    'Content-Disposition: form-data; name="metadata"',
    'Content-Type: application/json',
    '',
    JSON.stringify(metadata),
    `--${boundary}`,
    'Content-Disposition: form-data; name="fallback.js"; filename="fallback.js"',
    'Content-Type: application/javascript+module',
    '',
    site.workerSource,
    `--${boundary}--`,
    '',
  ].join('\r\n');
  const deployed = await cloudflare.request({
    method: 'PUT', path: base, body,
    contentType: `multipart/form-data; boundary=${boundary}`, rawBody: true,
  });
  if (!deployed.success) return { stage: 'deploy-assets', success: false, errors: deployed.errors };
  const preview = await cloudflare.request({ method: 'POST', path: `${base}/subdomain`, body: { enabled: true, previews_enabled: false } });
  return {
    success: preview.success,
    worker: site.name,
    deploymentId: deployed.result.deployment_id,
    etag: deployed.result.etag,
    previewEnabled: preview.success,
    errors: preview.errors,
  };
}
