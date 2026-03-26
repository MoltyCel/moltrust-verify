import { test, describe } from 'node:test';
import assert from 'node:assert';
import { MolTrustVerifier } from './index.js';
import type { VerifiableCredential } from './types.js';

const verifier = new MolTrustVerifier({ rpcUrl: 'https://mainnet.base.org' });

// Real anchored skill VC data from production
const ANCHORED_SKILL_TX = '0x35929779130718b2e5ca55af45923496accb6ec1d868aef9d968930fb35237a7' as const;
const ANCHORED_SKILL_HASH = 'sha256:ee9fd8343dc0a2e8f1e5cad1d050874cc7abb2291302351d547aa12f999db6f9';

// Real ERC-8004 agent ID (MolTrust agentId: 33553)
const ERC8004_AGENT_ID = 33553;

// TrustScout DID anchor TX
const TRUSTSCOUT_DID_TX = '0x75ea4e77071cb4efb77a9e97a0d7ee49d9914cd01477a37a299fa6bc749c275a' as const;

function makeVC(overrides: Partial<VerifiableCredential> = {}): VerifiableCredential {
  const now = new Date();
  const expires = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
  return {
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    type: ['VerifiableCredential', 'AgentTrustCredential'],
    issuer: 'did:web:moltrust.ch',
    issuanceDate: now.toISOString(),
    expirationDate: expires.toISOString(),
    credentialSubject: {
      id: 'did:moltrust:d34ed796a4dc4698',
      trustScore: 85,
    },
    proof: {
      type: 'JsonWebSignature2020',
      created: now.toISOString(),
      verificationMethod: 'did:web:moltrust.ch#moltguard-key-1',
      proofPurpose: 'assertionMethod',
      jws: 'eyJhbGciOiJFZERTQSJ9.test.signature',
    },
    ...overrides,
  };
}

describe('MolTrustVerifier — offline checks', () => {
  test('valid VC passes expiry check', () => {
    const vc = makeVC();
    assert.strictEqual(verifier.isExpired(vc), false);
  });

  test('expired VC fails expiry check', () => {
    const vc = makeVC({
      expirationDate: new Date(Date.now() - 86400000).toISOString(),
    });
    assert.strictEqual(verifier.isExpired(vc), true);
  });

  test('VC without expiry is not expired', () => {
    const vc = makeVC();
    delete (vc as any).expirationDate;
    assert.strictEqual(verifier.isExpired(vc), false);
  });

  test('computeHash returns consistent SHA-256', () => {
    const vc = makeVC();
    const hash1 = verifier.computeHash(vc);
    const hash2 = verifier.computeHash(vc);
    assert.strictEqual(hash1, hash2);
    assert.match(hash1, /^[a-f0-9]{64}$/);
  });

  test('extractDID returns credentialSubject.id', () => {
    const vc = makeVC();
    assert.strictEqual(verifier.extractDID(vc), 'did:moltrust:d34ed796a4dc4698');
  });
});

describe('MolTrustVerifier — on-chain verification', () => {
  test('verifyCredential with no anchor returns partial-onchain', async () => {
    const vc = makeVC();
    const result = await verifier.verifyCredential(vc);
    assert.strictEqual(result.valid, true);
    assert.strictEqual(result.method, 'partial-onchain');
    assert.strictEqual(result.checks.notExpired, true);
    assert.strictEqual(result.checks.hashAnchored, null);
    assert.strictEqual(result.checks.signatureVerified, null); // Fall C
    assert.ok(result.limitations.length > 0);
  });

  test('expired VC fails verification', async () => {
    const vc = makeVC({
      expirationDate: new Date(Date.now() - 86400000).toISOString(),
    });
    const result = await verifier.verifyCredential(vc);
    assert.strictEqual(result.valid, false);
    assert.strictEqual(result.checks.notExpired, false);
  });

  test('signatureVerified is null (Fall C — public key not on-chain)', async () => {
    const vc = makeVC();
    const result = await verifier.verifyCredential(vc);
    assert.strictEqual(result.checks.signatureVerified, null);
    assert.ok(result.limitations.some(l => l.includes('public key not on-chain')));
  });

  test('verifySkillAnchor against real Base TX', async () => {
    const result = await verifier.verifySkillAnchor(ANCHORED_SKILL_TX, ANCHORED_SKILL_HASH);
    assert.strictEqual(result.verified, true);
    assert.ok(result.blockNumber !== null);
    console.log(`  Skill anchor verified at block ${result.blockNumber}`);
  });

  test('verifyDIDAnchor against real TrustScout TX', async () => {
    const result = await verifier.verifyDIDAnchor(TRUSTSCOUT_DID_TX, 'did:moltrust:d34ed796a4dc4698');
    assert.strictEqual(result.verified, true);
    assert.ok(result.blockNumber !== null);
    console.log(`  DID anchor verified at block ${result.blockNumber}`);
  });

  test('resolveERC8004 for MolTrust agent 33553', async () => {
    const agent = await verifier.resolveERC8004(ERC8004_AGENT_ID);
    assert.strictEqual(agent.exists, true);
    assert.strictEqual(agent.agentId, ERC8004_AGENT_ID);
    assert.ok(agent.owner.startsWith('0x'));
    console.log(`  ERC-8004 agent ${ERC8004_AGENT_ID}: owner=${agent.owner}`);
  });

  test('resolveERC8004 for non-existent agent returns exists=false', async () => {
    const agent = await verifier.resolveERC8004(999999999);
    assert.strictEqual(agent.exists, false);
  });
});
