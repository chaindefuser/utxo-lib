/**
 * Implements hashing methods described in https://zips.z.cash/zip-0244.
 * Only supports full transparent transactions without shielded inputs or outputs.
 *
 * The transparent signature digest (S.2) follows the final ZIP-244 revision that activated with
 * NU5 (consensus branch 0xc2d6d0b4 onward): it commits to the `hash_type` byte and to the
 * amounts and scriptPubKeys of *all* transparent inputs, not just the one being signed.
 */
import { Transaction, TxInput, TxOutput } from 'bitcoinjs-lib';
import { BufferWriter } from 'bitcoinjs-lib/src/bufferutils';

const blake2b = require('@bitgo/blake2b');

import { ZcashTransaction } from './ZcashTransaction';
import { varSliceSize } from '../UtxoTransaction';

/** The coin spent by a transparent input: its value and scriptPubKey. */
export type ZcashPrevOutput<TNumber extends number | bigint = number> = {
  value: TNumber;
  script: Buffer;
};

type SignatureParams<TNumber extends number | bigint = number> = {
  /** Index of the transparent input being signed, or undefined for a shielded signature. */
  inIndex?: number;
  prevOutScript: Buffer;
  value: TNumber;
  hashType: number;
  /** The coins spent by every transparent input, in input order. */
  prevOutputs: ZcashPrevOutput<TNumber>[];
};

/**
 * Blake2b hashing algorithm for Zcash
 * @param buffer
 * @param personalization
 * @returns 256-bit BLAKE2b hash
 */
export function getBlake2bHash(buffer: Buffer, personalization: string | Buffer): Buffer {
  const out = Buffer.allocUnsafe(32);
  personalization = Buffer.from(personalization);
  return blake2b(out.length, null, null, personalization).update(buffer).digest(out);
}

function isAnyoneCanPay(hashType: number): boolean {
  return !!(hashType & Transaction.SIGHASH_ANYONECANPAY);
}

function baseHashType(hashType: number): number {
  return hashType & 0x1f;
}

function getHeaderDigest<TNumber extends number | bigint>(tx: ZcashTransaction<TNumber>): Buffer {
  // https://zips.z.cash/zip-0244#t-1-header-digest
  const mask = tx.overwintered ? 1 : 0;
  const writer = BufferWriter.withCapacity(4 * 5);
  writer.writeInt32(tx.version | (mask << 31)); // Set overwinter bit
  writer.writeUInt32(tx.versionGroupId);
  writer.writeUInt32(tx.consensusBranchId);
  writer.writeUInt32(tx.locktime);
  writer.writeUInt32(tx.expiryHeight);
  return getBlake2bHash(writer.end(), 'ZTxIdHeadersHash');
}

export function getPrevoutsDigest<TNumber extends number | bigint>(
  ins: TxInput[],
  tag = 'ZTxIdPrevoutHash',
  sigParams?: SignatureParams<TNumber>
): Buffer {
  // txid: https://zips.z.cash/zip-0244#t-2a-prevouts-digest
  // sig: https://zips.z.cash/zip-0244#s-2b-prevouts-sig-digest
  if (sigParams && isAnyoneCanPay(sigParams.hashType)) {
    return getPrevoutsDigest([]);
  }

  const bufferWriter = new BufferWriter(Buffer.allocUnsafe(36 * ins.length));
  ins.forEach(function (txIn) {
    bufferWriter.writeSlice(txIn.hash);
    bufferWriter.writeUInt32(txIn.index);
  });
  return getBlake2bHash(bufferWriter.end(), tag);
}

export function getAmountsSigDigest<TNumber extends number | bigint>(
  prevOutputs: ZcashPrevOutput<TNumber>[],
  hashType: number
): Buffer {
  // https://zips.z.cash/zip-0244#s-2c-amounts-sig-digest
  if (isAnyoneCanPay(hashType)) {
    prevOutputs = [];
  }
  const bufferWriter = new BufferWriter(Buffer.allocUnsafe(8 * prevOutputs.length));
  prevOutputs.forEach(function (prevOut) {
    bufferWriter.writeUInt64(prevOut.value);
  });
  return getBlake2bHash(bufferWriter.end(), 'ZTxTrAmountsHash');
}

export function getScriptPubKeysSigDigest<TNumber extends number | bigint>(
  prevOutputs: ZcashPrevOutput<TNumber>[],
  hashType: number
): Buffer {
  // https://zips.z.cash/zip-0244#s-2d-scriptpubkeys-sig-digest
  if (isAnyoneCanPay(hashType)) {
    prevOutputs = [];
  }
  const size = prevOutputs.reduce((sum, prevOut) => sum + varSliceSize(prevOut.script), 0);
  const bufferWriter = new BufferWriter(Buffer.allocUnsafe(size));
  prevOutputs.forEach(function (prevOut) {
    bufferWriter.writeVarSlice(prevOut.script);
  });
  return getBlake2bHash(bufferWriter.end(), 'ZTxTrScriptsHash');
}

export function getSequenceDigest<TNumber extends number | bigint>(
  ins: TxInput[],
  tag = 'ZTxIdSequencHash',
  sigParams?: SignatureParams<TNumber>
): Buffer {
  // txid: https://zips.z.cash/zip-0244#t-2b-sequence-digest
  // sig: https://zips.z.cash/zip-0244#s-2e-sequence-sig-digest
  // Unlike BIP-143, only SIGHASH_ANYONECANPAY blanks the sequence digest; SIGHASH_SINGLE and
  // SIGHASH_NONE still commit to every input's sequence number.
  if (sigParams && isAnyoneCanPay(sigParams.hashType)) {
    return getSequenceDigest([]);
  }

  const bufferWriter = new BufferWriter(Buffer.allocUnsafe(4 * ins.length));

  ins.forEach(function (txIn) {
    bufferWriter.writeUInt32(txIn.sequence);
  });

  return getBlake2bHash(bufferWriter.end(), tag);
}

export function getOutputsDigest<TNumber extends number | bigint>(
  outs: TxOutput<TNumber>[],
  tag = 'ZTxIdOutputsHash',
  sigParams?: SignatureParams<TNumber>
): Buffer {
  // txid: https://zips.z.cash/zip-0244#t-2c-outputs-digest
  // sig: https://zips.z.cash/zip-0244#s-2f-outputs-sig-digest
  if (sigParams) {
    const hashType = baseHashType(sigParams.hashType);

    if (hashType === Transaction.SIGHASH_SINGLE) {
      if (sigParams.inIndex === undefined) {
        throw new Error(`SIGHASH_SINGLE requires an input index`);
      }
      // SIGHASH_SINGLE without a corresponding output is a consensus failure; hash as empty.
      if (outs[sigParams.inIndex] === undefined) {
        return getOutputsDigest([]);
      }
      return getOutputsDigest([outs[sigParams.inIndex]]);
    }

    if (hashType === Transaction.SIGHASH_NONE) {
      return getOutputsDigest([]);
    }

    return getOutputsDigest(outs, tag);
  }

  // Find out the size of the outputs and write them
  const txOutsSize = outs.reduce(function (sum, output) {
    return sum + 8 + varSliceSize(output.script);
  }, 0);

  const bufferWriter = new BufferWriter(Buffer.allocUnsafe(txOutsSize));

  outs.forEach(function (out) {
    bufferWriter.writeUInt64(out.value);
    bufferWriter.writeVarSlice(out.script);
  });

  return getBlake2bHash(bufferWriter.end(), tag);
}

function getTxinDigest<TNumber extends number | bigint>(
  input: TxInput | undefined,
  sigParams: SignatureParams<TNumber>
): Buffer {
  // https://zips.z.cash/zip-0244#s-2g-txin-sig-digest
  if (input === undefined) {
    // Shielded signature: the txin digest is the hash of the empty byte string.
    return getBlake2bHash(Buffer.of(), 'Zcash___TxInHash');
  }
  const writer = BufferWriter.withCapacity(
    32 /* prevout hash */ +
      4 /* prevout vin */ +
      8 /* value */ +
      varSliceSize(sigParams.prevOutScript) +
      4 /* sequence */
  );
  writer.writeSlice(input.hash);
  writer.writeUInt32(input.index);
  writer.writeUInt64(sigParams.value);
  writer.writeVarSlice(sigParams.prevOutScript);
  writer.writeUInt32(input.sequence);
  return getBlake2bHash(writer.end(), 'Zcash___TxInHash');
}

function isCoinbase(ins: TxInput[]): boolean {
  return ins.length === 1 && Transaction.isCoinbaseHash(ins[0].hash) && ins[0].index === 0xffffffff;
}

function getTransparentDigest<TNumber extends number | bigint>(
  tx: { ins: TxInput[]; outs: TxOutput<TNumber>[] },
  sigParams?: SignatureParams<TNumber>
): Buffer {
  // txid: https://zips.z.cash/zip-0244#t-2-transparent-digest
  // sig: https://zips.z.cash/zip-0244#s-2-transparent-sig-digest
  //
  // The signature digest only differs from the txid digest for non-coinbase transactions that
  // have transparent inputs.
  if (sigParams && tx.ins.length && !isCoinbase(tx.ins)) {
    if (sigParams.prevOutputs.length !== tx.ins.length) {
      throw new Error(
        `ZIP-244 signature digest requires the prevout of every transparent input ` +
          `(got ${sigParams.prevOutputs.length}, expected ${tx.ins.length}): call setPrevOutputs() first`
      );
    }
    // A shielded signature over a transaction with transparent inputs behaves as SIGHASH_ALL.
    const hashType = sigParams.inIndex === undefined ? Transaction.SIGHASH_ALL : sigParams.hashType;
    const params: SignatureParams<TNumber> = { ...sigParams, hashType };

    const writer = BufferWriter.withCapacity(1 + 32 * 6);
    writer.writeUInt8(hashType);
    writer.writeSlice(getPrevoutsDigest(tx.ins, undefined, params));
    writer.writeSlice(getAmountsSigDigest(params.prevOutputs, hashType));
    writer.writeSlice(getScriptPubKeysSigDigest(params.prevOutputs, hashType));
    writer.writeSlice(getSequenceDigest(tx.ins, undefined, params));
    writer.writeSlice(getOutputsDigest(tx.outs, undefined, params));
    writer.writeSlice(getTxinDigest(params.inIndex === undefined ? undefined : tx.ins[params.inIndex], params));
    return getBlake2bHash(writer.end(), 'ZTxIdTranspaHash');
  }

  let buffer;
  if (tx.ins.length || tx.outs.length) {
    const writer = BufferWriter.withCapacity(32 * 3);
    writer.writeSlice(getPrevoutsDigest(tx.ins));
    writer.writeSlice(getSequenceDigest(tx.ins));
    writer.writeSlice(getOutputsDigest(tx.outs));
    buffer = writer.end();
  } else {
    buffer = Buffer.of();
  }
  return getBlake2bHash(buffer, 'ZTxIdTranspaHash');
}

function getSaplingDigest<TNumber extends number | bigint>(tx: ZcashTransaction<TNumber>): Buffer {
  // https://zips.z.cash/zip-0244#t-3-sapling-digest
  return getBlake2bHash(Buffer.of(), 'ZTxIdSaplingHash');
}

function getOrchardDigest<TNumber extends number | bigint>(tx: ZcashTransaction<TNumber>): Buffer {
  // https://zips.z.cash/zip-0244#t-4-orchard-digest
  return getBlake2bHash(Buffer.of(), 'ZTxIdOrchardHash');
}

/**
 * @param tx
 * @param signatureParams - calculates txid when undefined
 */
function getDigest<TNumber extends number | bigint>(
  tx: ZcashTransaction<TNumber>,
  signatureParams?: SignatureParams<TNumber>
): Buffer {
  // txid: https://zips.z.cash/zip-0244#id4
  // sig: https://zips.z.cash/zip-0244#id13
  const writer = BufferWriter.withCapacity(32 * 4);
  writer.writeSlice(getHeaderDigest(tx));
  writer.writeSlice(getTransparentDigest(tx, signatureParams));
  writer.writeSlice(getSaplingDigest(tx));
  writer.writeSlice(getOrchardDigest(tx));

  const tag = 'ZcashTxHash_';
  const personalization = BufferWriter.withCapacity(tag.length + 4 /* UInt32 */);
  personalization.writeSlice(Buffer.from(tag));
  personalization.writeUInt32(tx.consensusBranchId);
  return getBlake2bHash(writer.end(), personalization.end());
}

export function getTxidDigest<TNumber extends number | bigint>(tx: ZcashTransaction<TNumber>): Buffer {
  // https://zips.z.cash/zip-0244#id4
  return getDigest(tx);
}

/**
 * @param tx
 * @param inIndex - index of the transparent input being signed, or undefined for a shielded signature
 * @param prevOutScript - scriptPubKey of the coin spent by `inIndex`
 * @param value - value of the coin spent by `inIndex`
 * @param hashType
 * @param prevOutputs - value and scriptPubKey of the coins spent by every transparent input, in order
 */
export function getSignatureDigest<TNumber extends number | bigint>(
  tx: ZcashTransaction<TNumber>,
  inIndex: number | undefined,
  prevOutScript: Buffer,
  value: TNumber,
  hashType: number,
  prevOutputs: ZcashPrevOutput<TNumber>[]
): Buffer {
  // https://zips.z.cash/zip-0244#id13
  // S.2a: only these hash types are valid; anything else fails consensus validation.
  if (![0x01, 0x02, 0x03, 0x81, 0x82, 0x83].includes(hashType)) {
    throw new Error(`invalid ZIP-244 hash type 0x${hashType.toString(16)}`);
  }
  return getDigest(tx, {
    inIndex,
    prevOutScript,
    value,
    hashType,
    prevOutputs,
  });
}
