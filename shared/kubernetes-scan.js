// These exact schema releases are bundled in the scanner image, never fetched at runtime.
export const KUBERNETES_VERSIONS = Object.freeze(['1.32.0', '1.33.0', '1.34.0', '1.35.0']);
export const KUBERNETES_SCAN_TOOLS = Object.freeze(['k8s-deprecations', 'k8s-manifest-validate']);

export function kubernetesScanVersion(input) {
  const selected = input.tools?.some(tool => KUBERNETES_SCAN_TOOLS.includes(tool));
  if (selected && !KUBERNETES_VERSIONS.includes(input.kubernetesVersion))
    throw Object.assign(new Error(`Supply kubernetesVersion as one of: ${KUBERNETES_VERSIONS.join(', ')}.`), { status: 400 });
  if (!selected && input.kubernetesVersion !== undefined)
    throw Object.assign(new Error('kubernetesVersion requires a Kubernetes scan tool.'), { status: 400 });
  return selected ? input.kubernetesVersion : undefined;
}
