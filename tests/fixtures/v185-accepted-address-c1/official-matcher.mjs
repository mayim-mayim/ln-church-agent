// Finite offline diagnostic. Consume only synthetic actual executor captures.
// LN402_NODE_MODULES: isolated installation with @x402/core 2.19.0.
// Arguments: capture directory. No package dependency is added to the SDK.
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';
const modules = resolve(process.env.LN402_NODE_MODULES);
const esm = join(modules, '@x402/core/dist/esm/server/index.mjs');
const pkg = JSON.parse(readFileSync(join(modules, '@x402/core/package.json')));
assert.equal(pkg.version, '2.19.0');
const { x402ResourceServer } = await import(pathToFileURL(esm).href);
let externalCalls = 0, verifyCalls = 0;
globalThis.fetch = async () => { externalCalls++; throw Error('External network prohibited'); };
const facilitator = {
  getSupported: async () => ({ kinds: [{ x402Version: 2, scheme: 'exact', network: 'eip155:8453' }], extensions: [], signers: {} }),
  verify: async (payload) => { verifyCalls++; return { isValid: true, payer: payload.payload.authorization.from }; },
  settle: async () => { throw Error('Settlement is outside this matcher diagnostic'); }
};
const server = new x402ResourceServer(facilitator);
await server.initialize();
const results=[];
for (const name of readdirSync(process.argv[2]).sort()) {
  if (!name.endsWith('.json') || name.includes('alternatives')) continue;
  const capture=JSON.parse(readFileSync(join(process.argv[2],name)));
  assert.equal(capture.synthetic,true);
  const payload=JSON.parse(Buffer.from(capture.payment_signature,'base64').toString('utf8'));
  assert.deepEqual(payload,capture.actual_envelope);
  assert.equal(payload.payload.signature,'0x'+'00'.repeat(65));
  const before=verifyCalls;
  const selected=server.findMatchingRequirements(capture.seller_requirements,payload);
  assert.ok(selected, `${name}: actual emitted header failed official ESM matcher`);
  assert.equal((await server.verifyPayment(payload,selected)).isValid,true);
  assert.equal(verifyCalls-before,1);
  // Same actual capture, only accepted spelling reverted: historical negative.
  const normalized=structuredClone(payload);
  normalized.accepted.asset=normalized.accepted.asset.toLowerCase();
  normalized.accepted.payTo=normalized.accepted.payTo.toLowerCase();
  const spellingChanged=JSON.stringify(normalized.accepted)!==JSON.stringify(payload.accepted);
  const control=server.findMatchingRequirements(capture.seller_requirements,normalized);
  assert.equal(Boolean(control),!spellingChanged);
  results.push({case:capture.case,matched:true,synthetic_verify_calls:1,
    normalized_control_matches:!!control,stored_envelope_digest:capture.stored_envelope_digest});
}
assert.ok(results.length>=9);
assert.equal(externalCalls,0);
console.log(JSON.stringify({scope:'SDK actual executor headers / official matcher and synthetic verify only',
  node:process.version,version:pkg.version,esm_path:esm,
  esm_sha256:createHash('sha256').update(readFileSync(esm)).digest('hex'),
  results,verify_calls:verifyCalls,external_network_calls:externalCalls,
  target_http_calls:0,rpc_calls:0,real_signatures:0,real_payments:0,settlements:0},null,2));
