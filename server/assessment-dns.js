// A fixed resolver and bounded JSON response, shared by Node and Workers.
export async function assessmentDns(name, type, fetchImpl = fetch) {
  if (typeof name !== 'string' || !/^[a-zA-Z0-9_.-]{1,253}$/.test(name) || !['TXT', 'A', 'AAAA'].includes(type))
    throw new Error('Invalid DNS query.');
  const response = await fetchImpl(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`, {
    headers: { accept: 'application/dns-json' }, redirect: 'manual', signal: AbortSignal.timeout(10_000)
  });
  if (!response.ok || !response.body) throw new Error('Target DNS is unavailable.');
  const reader = response.body.getReader(); let text = '', bytes = 0;
  const decoder = new TextDecoder();
  try {
    while (true) {
      const { value, done } = await reader.read(); if (done) break;
      if ((bytes += value.byteLength) > 64 * 1024) throw new Error('Target DNS response is oversized.');
      text += decoder.decode(value, { stream: true });
    }
  } finally { await reader.cancel().catch(() => {}); }
  const result = JSON.parse(text + decoder.decode());
  if (![0, 3].includes(result.Status)) throw new Error('Target DNS resolution failed.');
  const numericType = { A: 1, AAAA: 28, TXT: 16 }[type];
  const records = (result.Answer || []).filter(item => item.type === numericType);
  if (records.length > 64) throw new Error('Too many target DNS answers.');
  return records.map(item => type === 'TXT' ? item.data.replace(/^"|"$/g, '').replace(/"\s+"/g, '') : item.data);
}

export const assessmentResolvers = {
  resolveTxt: name => assessmentDns(name, 'TXT'),
  resolveAddresses: async name => (await Promise.all([assessmentDns(name, 'A'), assessmentDns(name, 'AAAA')])).flat()
};
