import * as assert from 'assert';
import { ECPair, networks, Transaction, payments, script as bscript } from '../../../src';
import {
  getSignatureVerifications,
  verifySignature,
  ZcashPsbt,
  ZcashTransaction,
  ZcashTransactionBuilder,
  UnsupportedTransactionError,
} from '../../../src/bitgo';

/**
 * Regression tests for the v5 (ZIP-244) review findings: P2SH scriptCode vs scriptPubKey,
 * PSBT prevout wiring, verifySignature with prevOutputs, version defaults, coinbase digests and
 * re-verification of earlier signatures when prevouts are attached after a hex round-trip.
 */
describe('ZcashTransaction v5 review fixes', function () {
  const network = networks.zcash;
  const ZIP225_VERSION_GROUP_ID = 0x26a7270a;
  const NU6_3_BRANCH_ID = 0x37a5165b;
  const NU7_BRANCH_ID = 0x77190ad9;

  const keys = [1, 2, 3].map((i) => ECPair.fromPrivateKey(Buffer.alloc(32, i), { network }));
  const p2pkhA = payments.p2pkh({ pubkey: keys[0].publicKey, network }).output as Buffer;
  const p2ms = payments.p2ms({ m: 2, pubkeys: keys.map((k) => k.publicKey), network });
  const p2sh = payments.p2sh({ redeem: p2ms, network });
  const redeemScript = p2ms.output as Buffer;
  const p2shScriptPubKey = p2sh.output as Buffer;
  const dest = payments.p2pkh({ pubkey: ECPair.fromPrivateKey(Buffer.alloc(32, 9), { network }).publicKey, network })
    .output as Buffer;

  function newBuilder(branchId = NU7_BRANCH_ID): ZcashTransactionBuilder {
    const txb = new ZcashTransactionBuilder(network);
    txb.setVersion(5, true);
    txb.setVersionGroupId(ZIP225_VERSION_GROUP_ID);
    txb.setConsensusBranchId(branchId);
    txb.setExpiryHeight(3_543_600);
    return txb;
  }

  function verifyP2pkhInput(tx: ZcashTransaction, vin: number, key: ReturnType<typeof ECPair.fromPrivateKey>) {
    const [sigChunk, pubkey] = bscript.decompile(tx.ins[vin].script) as Buffer[];
    const { signature, hashType } = bscript.signature.decode(sigChunk);
    assert.ok(pubkey.equals(key.publicKey));
    const prev = tx.prevOutputs![vin];
    const digest = tx.hashForSignatureByNetwork(vin, prev.script, prev.value, hashType);
    assert.ok(key.verify(digest, signature), `input ${vin} signature`);
  }

  describe('P2SH multisig (scriptCode != scriptPubKey)', function () {
    it('signs a single-input p2sh-p2ms v5 tx against the scriptPubKey, not the redeemScript', function () {
      const txb = newBuilder();
      txb.addInput(Buffer.alloc(32, 0xaa), 0);
      txb.addOutput(dest, 90_000);
      // The builder passes the redeemScript as scriptCode; the digest must still commit to the
      // p2sh scriptPubKey. Without this, the single-input fallback would hash the redeemScript.
      txb.sign(0, keys[0], redeemScript, Transaction.SIGHASH_ALL, 100_000);
      txb.sign(0, keys[1], redeemScript, Transaction.SIGHASH_ALL, 100_000);
      const tx = txb.build();

      // Independent check: recompute the digest from an explicit prevout list.
      const check = ZcashTransaction.fromBuffer(tx.toBuffer(), false, 'number', network);
      check.setPrevOutputs([{ value: 100_000, script: p2shScriptPubKey }]);
      const chunks = bscript.decompile(check.ins[0].script) as Buffer[];
      const sigs = chunks.slice(1, 3).map((c) => bscript.signature.decode(c));
      const digest = check.hashForSignatureByNetwork(0, redeemScript, 100_000, Transaction.SIGHASH_ALL);
      assert.ok(keys[0].verify(digest, sigs[0].signature));
      assert.ok(keys[1].verify(digest, sigs[1].signature));

      // And the wrong digest (redeemScript as scriptPubKey) must NOT verify.
      const wrong = ZcashTransaction.fromBuffer(tx.toBuffer(), false, 'number', network);
      wrong.setPrevOutputs([{ value: 100_000, script: redeemScript }]);
      const wrongDigest = wrong.hashForSignatureByNetwork(0, redeemScript, 100_000, Transaction.SIGHASH_ALL);
      assert.ok(!keys[0].verify(wrongDigest, sigs[0].signature));
    });

    it('signs a two-input tx mixing p2sh-p2ms and p2pkh with prevouts set explicitly', function () {
      const txb = newBuilder();
      txb.addInput(Buffer.alloc(32, 0xaa), 0);
      txb.addInput(Buffer.alloc(32, 0xbb), 1);
      txb.addOutput(dest, 150_000);
      txb.setPrevOutputs([
        { value: 100_000, script: p2shScriptPubKey },
        { value: 60_000, script: p2pkhA },
      ]);
      txb.sign(0, keys[0], redeemScript, Transaction.SIGHASH_ALL, 100_000);
      txb.sign(0, keys[2], redeemScript, Transaction.SIGHASH_ALL, 100_000);
      txb.sign(1, keys[0], undefined, Transaction.SIGHASH_ALL, 60_000);
      const tx = txb.build();
      tx.setPrevOutputs([
        { value: 100_000, script: p2shScriptPubKey },
        { value: 60_000, script: p2pkhA },
      ]);
      verifyP2pkhInput(tx, 1, keys[0]);
      // getSignatureVerifications / verifySignature take prevOutputs and must forward them.
      const parsed = ZcashTransaction.fromBuffer(tx.toBuffer(), false, 'number', network);
      const prevOutputs = [
        { value: 100_000, script: p2shScriptPubKey },
        { value: 60_000, script: p2pkhA },
      ];
      const verifications = getSignatureVerifications(parsed, 0, 100_000, {}, prevOutputs);
      assert.strictEqual(verifications.length, 2);
      assert.ok(verifications.every((v) => v.signedBy !== undefined));
      assert.strictEqual(verifySignature(parsed, 0, 100_000, { publicKey: keys[2].publicKey }, prevOutputs), true);
      assert.strictEqual(verifySignature(parsed, 0, 100_000, { publicKey: keys[1].publicKey }, prevOutputs), false);
    });

    it('fills prevouts from input metadata when sign() gets the values', function () {
      const txb = newBuilder();
      txb.addInput(Buffer.alloc(32, 0xaa), 0, undefined, p2shScriptPubKey);
      txb.addInput(Buffer.alloc(32, 0xbb), 1, undefined, p2pkhA);
      txb.addOutput(dest, 150_000);
      // No setPrevOutputs: the scripts come from addInput and the values from sign().
      assert.throws(() => txb.sign(0, keys[0], redeemScript, Transaction.SIGHASH_ALL, 100_000), /setPrevOutputs/);
      // ...which only works once every input's value is known (the lib cannot guess input 1's).
      ((txb as any).__INPUTS[1] as any).value = 60_000;
      txb.sign(0, keys[0], redeemScript, Transaction.SIGHASH_ALL, 100_000);
      assert.deepStrictEqual(
        txb.tx.prevOutputs!.map((p) => ({ value: p.value, script: p.script.toString('hex') })),
        [
          { value: 100_000, script: p2shScriptPubKey.toString('hex') },
          { value: 60_000, script: p2pkhA.toString('hex') },
        ]
      );
    });
  });

  describe('second review', function () {
    function p2msSignedByFirstAndThird(): { hex: string; prevOutputs: { value: number; script: Buffer }[] } {
      const txb = newBuilder();
      txb.addInput(Buffer.alloc(32, 0xaa), 0);
      txb.addInput(Buffer.alloc(32, 0xbb), 1);
      txb.addOutput(dest, 150_000);
      const prevOutputs = [
        { value: 100_000, script: p2shScriptPubKey },
        { value: 60_000, script: p2pkhA },
      ];
      txb.setPrevOutputs(prevOutputs);
      // keys[0] and keys[2]: the scriptSig holds [sig0, sig2], which is NOT pubkey-aligned
      // ([pk0, pk1, pk2]) once parsed back from hex.
      txb.sign(0, keys[0], redeemScript, Transaction.SIGHASH_ALL, 100_000);
      txb.sign(0, keys[2], redeemScript, Transaction.SIGHASH_ALL, 100_000);
      return { hex: txb.buildIncomplete().toHex(), prevOutputs };
    }

    it('re-aligns 2-of-3 signatures parsed from hex before verifying them (#1)', function () {
      const { hex, prevOutputs } = p2msSignedByFirstAndThird();
      const parsed = ZcashTransaction.fromBuffer(Buffer.from(hex, 'hex'), true, 'number', network);
      // via fromTransaction(prevOutputs)
      const a = ZcashTransactionBuilder.fromTransaction(parsed, network, prevOutputs);
      a.sign(1, keys[0]);
      const built = a.build();
      built.setPrevOutputs(prevOutputs);
      verifyP2pkhInput(built, 1, keys[0]);
      assert.strictEqual(getSignatureVerifications(built, 0, 100_000, {}, prevOutputs).length, 2);
      // via fromTransaction() + setPrevOutputs()
      const b = ZcashTransactionBuilder.fromTransaction(parsed, network);
      assert.doesNotThrow(() => b.setPrevOutputs(prevOutputs));
      assert.throws(
        () => ZcashTransactionBuilder.fromTransaction(parsed, network).setPrevOutputs([
          { value: 100_001, script: p2shScriptPubKey },
          prevOutputs[1],
        ]),
        /does not verify/
      );
    });

    it('refuses the single-input fallback for a P2SH scriptCode (#2)', function () {
      const tx = new ZcashTransaction(network);
      tx.version = 5;
      tx.overwintered = 1;
      tx.versionGroupId = ZIP225_VERSION_GROUP_ID;
      tx.consensusBranchId = NU7_BRANCH_ID;
      tx.addInput(Buffer.alloc(32, 0xaa), 0);
      tx.addOutput(dest, 90_000);
      assert.throws(
        () => tx.hashForSignatureByNetwork(0, redeemScript, 100_000, Transaction.SIGHASH_ALL),
        /setPrevOutputs/
      );
      // P2PKH scriptCode is the scriptPubKey: still fine without prevouts.
      assert.doesNotThrow(() => tx.hashForSignatureByNetwork(0, p2pkhA, 100_000, Transaction.SIGHASH_ALL));
      // Explicit prevouts take precedence and work for P2SH.
      assert.doesNotThrow(() =>
        tx.hashForSignatureByNetwork(0, redeemScript, 100_000, Transaction.SIGHASH_ALL, [
          { value: 100_000, script: p2shScriptPubKey },
        ])
      );
    });

    it('PSBT prevouts follow later input changes (#3, #4)', function () {
      const psbt = ZcashPsbt.createPsbt({ network });
      psbt.setDefaultsForVersion(network, ZcashTransaction.VERSION5_BRANCH_NU7);
      psbt.addInput({ hash: Buffer.alloc(32, 0xaa), index: 0, witnessUtxo: { script: p2pkhA, value: BigInt(100_000) } });
      psbt.addInput({ hash: Buffer.alloc(32, 0xbb), index: 1 });
      psbt.addOutput({ script: dest, value: BigInt(150_000) });
      // Input 1 has no UTXO data yet: signing input 0 must fail loudly, not hash a stale/partial list.
      assert.throws(() => psbt.signInput(0, keys[0]), /setPrevOutputs|Utxo/);
      psbt.updateInput(1, { witnessUtxo: { script: p2pkhA, value: BigInt(60_000) } });
      psbt.signInput(0, keys[0]);
      psbt.signInput(1, keys[0]);
      assert.strictEqual(psbt.validateSignaturesOfAllInputs(), true);
      // A malformed nonWitnessUtxo (output index out of range) is reported clearly.
      const bad = ZcashPsbt.createPsbt({ network });
      bad.setDefaultsForVersion(network, ZcashTransaction.VERSION5_BRANCH_NU7);
      const prevTx = newBuilder();
      prevTx.addInput(Buffer.alloc(32, 0xcc), 0);
      prevTx.addOutput(p2pkhA, 100_000);
      const prevTxBuf = prevTx.buildIncomplete().toBuffer();
      const prevHash = prevTx.buildIncomplete().getHash();
      bad.addInput({ hash: prevHash, index: 7, nonWitnessUtxo: prevTxBuf });
      bad.addOutput({ script: dest, value: BigInt(90_000) });
      assert.throws(() => bad.signInput(0, keys[0]), /has no output 7/);
    });

    it('verifySignature does not store prevouts on the caller transaction (#5)', function () {
      const { hex, prevOutputs } = p2msSignedByFirstAndThird();
      const parsed = ZcashTransaction.fromBuffer(Buffer.from(hex, 'hex'), true, 'number', network);
      assert.strictEqual(parsed.prevOutputs, undefined);
      assert.strictEqual(getSignatureVerifications(parsed, 0, 100_000, {}, prevOutputs).length, 2);
      assert.strictEqual(parsed.prevOutputs, undefined);
      // Wrong prevouts passed later are honoured (they are not shadowed by a cached copy).
      assert.throws(() =>
        getSignatureVerifications(parsed, 0, 100_000, {}, [{ value: 100_001, script: p2pkhA }, prevOutputs[1]])
      );
    });

    it('rejects undefined hash types (#7)', function () {
      const tx = new ZcashTransaction(network);
      tx.version = 5;
      tx.overwintered = 1;
      tx.versionGroupId = ZIP225_VERSION_GROUP_ID;
      tx.consensusBranchId = NU7_BRANCH_ID;
      tx.addInput(Buffer.alloc(32, 0xaa), 0);
      tx.addOutput(dest, 90_000);
      assert.throws(() => tx.hashForSignatureByNetwork(0, p2pkhA, 100_000, 0x41), /invalid ZIP-244 hash type/);
    });
  });

  describe('round-trip and prevout integrity', function () {
    function partiallySigned(): { hex: string; prevOutputs: { value: number; script: Buffer }[] } {
      const txb = newBuilder();
      txb.addInput(Buffer.alloc(32, 0xaa), 0);
      txb.addInput(Buffer.alloc(32, 0xbb), 1);
      txb.addOutput(dest, 150_000);
      const prevOutputs = [
        { value: 100_000, script: p2pkhA },
        { value: 60_000, script: p2pkhA },
      ];
      txb.setPrevOutputs(prevOutputs);
      txb.sign(0, keys[0], undefined, Transaction.SIGHASH_ALL, 100_000);
      return { hex: txb.buildIncomplete().toHex(), prevOutputs };
    }

    it('rejects prevouts that do not match an existing signature after a hex round-trip', function () {
      const { hex, prevOutputs } = partiallySigned();
      const tx = ZcashTransaction.fromBuffer(Buffer.from(hex, 'hex'), true, 'number', network);
      const txb = ZcashTransactionBuilder.fromTransaction(tx, network);
      assert.throws(
        () => txb.setPrevOutputs([prevOutputs[0], { value: 60_001, script: p2pkhA }]),
        /does not verify against the given prevOutputs/
      );
      assert.strictEqual(txb.tx.prevOutputs, undefined);
      assert.doesNotThrow(() => txb.setPrevOutputs(prevOutputs));
    });

    it('fromTransaction(prevOutputs) fills value and prevOutScript so sign() needs no value', function () {
      const { hex, prevOutputs } = partiallySigned();
      const tx = ZcashTransaction.fromBuffer(Buffer.from(hex, 'hex'), true, 'number', network);
      const txb = ZcashTransactionBuilder.fromTransaction(tx, network, prevOutputs);
      const inputs = (txb as any).__INPUTS;
      assert.strictEqual(inputs[1].value, 60_000);
      assert.ok(inputs[1].prevOutScript.equals(p2pkhA));
      txb.sign(1, keys[0]);
      const signed = txb.build();
      signed.setPrevOutputs(prevOutputs);
      verifyP2pkhInput(signed, 0, keys[0]);
      verifyP2pkhInput(signed, 1, keys[0]);
    });
  });

  describe('PSBT', function () {
    it('signs and validates a two-input v5 PSBT using witnessUtxo prevouts', function () {
      const psbt = ZcashPsbt.createPsbt({ network });
      psbt.setDefaultsForVersion(network, ZcashTransaction.VERSION5_BRANCH_NU7);
      const unsigned = (psbt as any).tx as ZcashTransaction<bigint>;
      assert.strictEqual(unsigned.version, 5);
      assert.strictEqual(unsigned.consensusBranchId, NU7_BRANCH_ID);
      psbt.addInput({
        hash: Buffer.alloc(32, 0xaa),
        index: 0,
        witnessUtxo: { script: p2pkhA, value: BigInt(100_000) },
      });
      psbt.addInput({
        hash: Buffer.alloc(32, 0xbb),
        index: 1,
        witnessUtxo: { script: p2shScriptPubKey, value: BigInt(60_000) },
        redeemScript,
      });
      psbt.addOutput({ script: dest, value: BigInt(150_000) });

      psbt.signInput(0, keys[0]);
      psbt.signInput(1, keys[1]);
      psbt.signInput(1, keys[2]);
      assert.strictEqual(psbt.validateSignaturesOfAllInputs(), true);
      psbt.finalizeAllInputs();
      const tx = psbt.extractTransaction() as ZcashTransaction<bigint>;
      assert.strictEqual(tx.version, 5);
      assert.ok(unsigned.prevOutputs, 'prevouts were attached to the unsigned tx');
      const parsed = ZcashTransaction.fromBuffer(tx.toBuffer(), false, 'number', network);
      parsed.setPrevOutputs([
        { value: 100_000, script: p2pkhA },
        { value: 60_000, script: p2shScriptPubKey },
      ]);
      verifyP2pkhInput(parsed, 0, keys[0]);
      const verifications = getSignatureVerifications(parsed, 1, 60_000, {}, parsed.prevOutputs);
      assert.strictEqual(verifications.length, 2);
      assert.ok(verifications.every((v) => v.signedBy !== undefined));
    });
  });

  describe('defaults and versions', function () {
    it('keeps bare version 5 on NU6.3 and maps VERSION5_BRANCH_NU7 to NU7', function () {
      const v5 = new ZcashTransactionBuilder(network);
      v5.setDefaultsForVersion(network, 5);
      assert.strictEqual(v5.tx.consensusBranchId, NU6_3_BRANCH_ID);
      const nu7 = new ZcashTransactionBuilder(network);
      nu7.setDefaultsForVersion(network, ZcashTransaction.VERSION5_BRANCH_NU7);
      assert.strictEqual(nu7.tx.version, 5);
      assert.strictEqual(nu7.tx.versionGroupId, ZIP225_VERSION_GROUP_ID);
      assert.strictEqual(nu7.tx.consensusBranchId, NU7_BRANCH_ID);
      const psbt = ZcashPsbt.createPsbt({ network });
      assert.doesNotThrow(() => psbt.setDefaultsForVersion(network, ZcashTransaction.VERSION5_BRANCH_NU7));
    });
  });

  describe('coinbase', function () {
    it('computes a shielded-style digest for a coinbase v5 tx without prevouts', function () {
      const tx = new ZcashTransaction(network);
      tx.version = 5;
      tx.overwintered = 1;
      tx.versionGroupId = ZIP225_VERSION_GROUP_ID;
      tx.consensusBranchId = NU7_BRANCH_ID;
      tx.addInput(Buffer.alloc(32, 0), 0xffffffff, 0xffffffff, Buffer.from('0300d3d1', 'hex'));
      tx.addOutput(dest, 625_000_000);
      assert.doesNotThrow(() => tx.hashForSignatureByNetwork(undefined, Buffer.of(), 0, Transaction.SIGHASH_ALL));
      assert.ok(tx.getHash().length === 32);
    });
  });

  it('still rejects shielded transactions', function () {
    // Sanity: nothing above loosened the transparent-only parser.
    assert.throws(
      () =>
        ZcashTransaction.fromBuffer(
          Buffer.from('050000800a27a726b4d0d6c2000000000000000000000001', 'hex'),
          true,
          'number',
          network
        ),
      (e: unknown) => e instanceof UnsupportedTransactionError || e instanceof Error
    );
  });
});
