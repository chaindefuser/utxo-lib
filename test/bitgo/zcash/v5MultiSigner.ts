import * as assert from 'assert';
import { ECPair, networks, Transaction } from '../../../src';
import { ZcashTransaction, ZcashTransactionBuilder } from '../../../src/bitgo';
import { payments } from 'bitcoinjs-lib';

/**
 * Exercises the flow used by poa-bridge for the legacy-PDS ZEC forward: a v5 (NU7) transaction
 * with inputs owned by two different keys, signed in two rounds where each signer only holds
 * its own key, and the partially signed transaction travels between the rounds as hex.
 */
describe('ZcashTransaction v5 multi-signer', function () {
  const network = networks.zcash;
  const ZIP225_VERSION_GROUP_ID = 0x26a7270a;
  const NU7_BRANCH_ID = 0x77190ad9;

  const keyA = ECPair.fromPrivateKey(Buffer.alloc(32, 1), { network });
  const keyB = ECPair.fromPrivateKey(Buffer.alloc(32, 2), { network });
  const scriptA = payments.p2pkh({ pubkey: keyA.publicKey, network }).output as Buffer;
  const scriptB = payments.p2pkh({ pubkey: keyB.publicKey, network }).output as Buffer;
  const dest = payments.p2pkh({ pubkey: ECPair.fromPrivateKey(Buffer.alloc(32, 3), { network }).publicKey, network })
    .output as Buffer;

  const inputs = [
    { hash: Buffer.alloc(32, 0xaa), index: 0, value: 48_000_000, script: scriptA }, // deposit address
    { hash: Buffer.alloc(32, 0xbb), index: 2, value: 10_000, script: scriptB }, // gas refuller
  ];
  const prevOutputs = inputs.map((i) => ({ value: i.value, script: i.script }));

  function buildUnsigned(): ZcashTransactionBuilder {
    const txb = new ZcashTransactionBuilder(network);
    txb.setVersion(5, true);
    txb.setVersionGroupId(ZIP225_VERSION_GROUP_ID);
    txb.setConsensusBranchId(NU7_BRANCH_ID);
    txb.setExpiryHeight(3_543_600);
    txb.setLockTime(0);
    inputs.forEach((i) => txb.addInput(i.hash, i.index));
    txb.addOutput(dest, 48_000_000);
    txb.addOutput(scriptB, 5_000);
    txb.setPrevOutputs(prevOutputs);
    return txb;
  }

  function reattach(hex: string): ZcashTransactionBuilder {
    const tx = ZcashTransaction.fromBuffer(Buffer.from(hex, 'hex'), true, 'number', network);
    const txb = ZcashTransactionBuilder.fromTransaction(tx, network);
    txb.setConsensusBranchId(NU7_BRANCH_ID);
    txb.setPrevOutputs(prevOutputs);
    return txb;
  }

  it('signs in two rounds and every signature verifies against the ZIP-244 digest', function () {
    // Round 1: gas-refuller key signs only its input.
    const round1 = buildUnsigned();
    round1.sign(1, keyB, undefined, Transaction.SIGHASH_ALL, inputs[1].value);
    const partialHex = round1.buildIncomplete().toHex();

    // Round 2: deposit-address key signs its input on the round-tripped partial tx.
    const round2 = reattach(partialHex);
    round2.sign(0, keyA, undefined, Transaction.SIGHASH_ALL, inputs[0].value);
    const signed = round2.build();

    assert.strictEqual(signed.version, 5);
    assert.strictEqual(signed.versionGroupId, ZIP225_VERSION_GROUP_ID);
    assert.strictEqual(signed.consensusBranchId, NU7_BRANCH_ID);

    // Verify each input's signature against the digest an independent verifier would compute.
    const verifier = ZcashTransaction.fromBuffer(signed.toBuffer(), true, 'number', network);
    verifier.consensusBranchId = NU7_BRANCH_ID;
    verifier.setPrevOutputs(prevOutputs);
    [keyA, keyB].forEach((key, i) => {
      const chunks = require('bitcoinjs-lib').script.decompile(verifier.ins[i].script) as Buffer[];
      const sig = require('bitcoinjs-lib').script.signature.decode(chunks[0]);
      assert.strictEqual(sig.hashType, Transaction.SIGHASH_ALL);
      assert.ok(chunks[1].equals(key.publicKey), `input ${i} pubkey`);
      const digest = verifier.hashForSignatureByNetwork(i, inputs[i].script, inputs[i].value, sig.hashType);
      assert.ok(key.verify(digest, sig.signature), `input ${i} signature`);
    });
  });

  it('round-tripped partial tx keeps the first signature intact', function () {
    const round1 = buildUnsigned();
    round1.sign(1, keyB, undefined, Transaction.SIGHASH_ALL, inputs[1].value);
    const partialHex = round1.buildIncomplete().toHex();
    const again = reattach(partialHex).buildIncomplete().toHex();
    assert.strictEqual(again, partialHex);
  });

  it('refuses to sign a multi-input v5 tx without prevouts', function () {
    const txb = buildUnsigned();
    txb.tx.prevOutputs = undefined;
    assert.throws(() => txb.sign(0, keyA, undefined, Transaction.SIGHASH_ALL, inputs[0].value), /setPrevOutputs/);
  });

  it('refuses to change prevouts under an existing signature', function () {
    const txb = buildUnsigned();
    txb.sign(1, keyB, undefined, Transaction.SIGHASH_ALL, inputs[1].value);
    assert.throws(
      () => txb.setPrevOutputs([{ value: 1, script: scriptA }, prevOutputs[1]]),
      /would invalidate signatures/
    );
    assert.doesNotThrow(() => txb.setPrevOutputs(prevOutputs));
  });
});
