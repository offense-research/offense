import test from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createMcpServer, MCP_TOOL_NAME, LEGACY_MCP_TOOL_NAME } from '../lib/mcp.mjs';
import { auditMetadata } from '../lib/audit.mjs';

const files = [{ path: 'package-lock.json', content: JSON.stringify({ lockfileVersion: 3, packages: { '': { dependencies: { semver: '^7.5.1' } }, 'node_modules/semver': { version: '7.5.1' } } }) }];
async function connection(t, intelligence) {
  const server = createMcpServer({ intelligence });
  const client = new Client({ name: 'purple-local-fixture', version: '1.0.0' });
  const [left, right] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(left), client.connect(right)]);
  t.after(async () => { await client.close(); await server.close(); });
  return client;
}

test('MCP exposes only the metadata audit capability with explicit limits', async t => {
  const client = await connection(t, { audit: () => { throw Error('Discovery must not audit'); } });
  const listed = await client.listTools(); assert.equal(listed.tools.length, 2);
  const tool = listed.tools[0]; assert.equal(tool.name, MCP_TOOL_NAME);
  assert.equal(tool.annotations.readOnlyHint, true); assert.equal(tool.annotations.destructiveHint, false);
  assert.equal(tool.inputSchema.additionalProperties, false);
  assert.equal(tool.inputSchema.properties.files.maxItems, 20);
});

test('MCP audit returns direct local-engine results without model/tool execution', async t => {
  const client = await connection(t, { audit: input => auditMetadata(input, { check: async () => ({ status: 'complete', findings: [], checkedPackages: 1 }) }) });
  const result = await client.callTool({ name: MCP_TOOL_NAME, arguments: { files, planLimit: 0 } });
  assert.equal(result.isError, undefined); assert.equal(result.structuredContent.schemaVersion, 'purple.audit.v1');
  assert.equal(result.structuredContent.summary.confirmedVulnerabilities, 0);
  assert.deepEqual(result.structuredContent.providers.map(p => p.id), ['osv']);
});

test('MCP validation failures are explicit errors rather than clean reports', async t => {
  const client = await connection(t, { audit: input => auditMetadata(input, { fetchImpl: () => { throw Error('No network allowed'); } }) });
  const result = await client.callTool({ name: MCP_TOOL_NAME, arguments: { files: [{ path: '../private.env', content: '{}' }] } });
  assert.equal(result.isError, true); assert.equal(result.structuredContent, undefined);
  assert.equal(JSON.parse(result.content[0].text).status, 'error');
});

test('actual CLI stdio MCP initializes and discovers tools without account configuration', async t => {
  const transport = new StdioClientTransport({ command: process.execPath,
    args: [fileURLToPath(new URL('../bin/offense.mjs', import.meta.url)), 'mcp'],
    env: { PATH: process.env.PATH, HOME: '/tmp', NODE_OPTIONS: '' }, stderr: 'pipe' });
  const client = new Client({ name: 'purple-stdio-fixture', version: '1.0.0' });
  t.after(() => client.close());
  await client.connect(transport);
  assert.equal(client.getServerVersion().name, 'offense-community');
  assert.deepEqual((await client.listTools()).tools.map(tool => tool.name), [MCP_TOOL_NAME, LEGACY_MCP_TOOL_NAME]);
});

test('legacy audit tool remains an alias of the same local capability', async t => {
  const client = await connection(t, { audit: input => auditMetadata(input, { check: async () => ({ status: 'complete', findings: [], checkedPackages: 1 }) }) });
  const result = await client.callTool({ name: LEGACY_MCP_TOOL_NAME, arguments: { files, planLimit: 0 } });
  assert.equal(result.isError, undefined);
  assert.equal(result.structuredContent.schemaVersion, 'purple.audit.v1');
  assert.equal(result.structuredContent.summary.confirmedVulnerabilities, 0);
});
