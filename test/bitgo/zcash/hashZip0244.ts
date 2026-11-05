import * as assert from 'assert';
import * as vectors from './fixtures/vectorsZip0244.json';
import { UnsupportedTransactionError, ZcashTransaction } from '../../../src/bitgo';
import { Transaction, networks } from '../../../src';

// Columns of https://github.com/zcash/zcash-test-vectors/blob/master/test-vectors/json/zip_0244.json
type Vector = [
  tx: string,
  txid: string,
  auth_digest: string,
  amounts: number[],
  script_pubkeys: string[],
  transparent_input: number | null,
  sighash_shielded: string,
  sighash_all: string | null,
  sighash_none: string | null,
  sighash_single: string | null,
  sighash_all_anyone: string | null,
  sighash_none_anyone: string | null,
  sighash_single_anyone: string | null,
];

function parseHashType(hashTypeStr: string): number {
  return hashTypeStr.split('|').reduce((v, str) => {
    if (str in Transaction) {
      return v | Transaction[str];
    }
    throw new Error(`invalid hashType ${str}`);
  }, 0);
}

function runVector(v: Vector, i: number) {
  const [
    txHex,
    txid,
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    authDigest,
    amounts,
    scriptPubKeys,
    transparentInput,
    sighashShielded,
    ...sigHashHex /* sighash_all, sighash_none, sighash_single, sighash_all_anyone, sighash_none_anyone, sighash_single_anyone */
  ] = v;

  describe(`Vector ${i}, txid=${txid}`, function () {
    let tx: ZcashTransaction;
    before('parse', function () {
      try {
        tx = ZcashTransaction.fromBuffer(Buffer.from(txHex, 'hex'), false, 'number', networks.zcash);
      } catch (e) {
        if (e instanceof UnsupportedTransactionError) {
          this.skip();
        }
        throw e;
      }
      tx.setPrevOutputs(amounts.map((value, i) => ({ value, script: Buffer.from(scriptPubKeys[i], 'hex') })));
    });

    it('has expected txid', function () {
      // getId() returns the reversed hash
      assert.strictEqual(tx.getHash().toString('hex'), txid);
    });

    it('has expected value for shielded signature', function () {
      // A shielded signature does not pick an input: value/script are irrelevant.
      assert.strictEqual(
        tx.hashForSignatureByNetwork(undefined, Buffer.of(), 0, Transaction.SIGHASH_ALL).toString('hex'),
        sighashShielded
      );
    });

    if (transparentInput === null) {
      return;
    }

    [
      'SIGHASH_ALL',
      'SIGHASH_NONE',
      'SIGHASH_SINGLE',
      'SIGHASH_ALL|SIGHASH_ANYONECANPAY',
      'SIGHASH_NONE|SIGHASH_ANYONECANPAY',
      'SIGHASH_SINGLE|SIGHASH_ANYONECANPAY',
    ].forEach((hashTypeStr, i) => {
      if (sigHashHex[i] === null) {
        return;
      }
      const hashType = parseHashType(hashTypeStr);
      it(`has expected value for ${hashTypeStr} ${hashType}`, function () {
        assert.strictEqual(
          tx
            .hashForSignatureByNetwork(
              transparentInput,
              Buffer.from(scriptPubKeys[transparentInput], 'hex'),
              amounts[transparentInput],
              hashType
            )
            .toString('hex'),
          sigHashHex[i]
        );
      });
    });

    it('rejects signing without prevOutputs when there are several inputs', function (this: Mocha.Context) {
      if (tx.ins.length < 2) {
        this.skip();
      }
      const bare = tx.clone();
      bare.prevOutputs = undefined;
      assert.throws(
        () =>
          bare.hashForSignatureByNetwork(
            transparentInput,
            Buffer.from(scriptPubKeys[transparentInput], 'hex'),
            amounts[transparentInput],
            Transaction.SIGHASH_ALL
          ),
        /setPrevOutputs/
      );
    });

    it('rejects a value that does not match prevOutputs', function () {
      assert.throws(
        () =>
          tx.hashForSignatureByNetwork(
            transparentInput,
            Buffer.from(scriptPubKeys[transparentInput], 'hex'),
            amounts[transparentInput] + 1,
            Transaction.SIGHASH_ALL
          ),
        /does not match/
      );
    });
  });
}

describe('ZcashTransaction ZIP-0244', function () {
  vectors
    .filter((v) => v.length > 1)
    .forEach((v, i) => {
      runVector(v as Vector, i);
    });
});
