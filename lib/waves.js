require('./helper/converters.js');
var converters = require('./helper/converters').default;
var blake2b = require('./helper/blake2b');
var sha3 = require('./helper/sha3');
var SHA256_hash = require('./helper/jssha256');
var curve25519 = require('./helper/curve25519');
var Base58 = require('./helper/base58');

var Waves = {};
Waves.epoch = 1460678400;

Waves.getPublicKey = function (secretPhrase) {
  return this.buildPublicKey(converters.stringToByteArray(secretPhrase));
};

Waves.getPrivateKey = function (secretPhrase) {
  return this.buildPrivateKey(converters.stringToByteArray(secretPhrase));
};

Waves.appendUint8Arrays = function (array1, array2) {
  var tmp = new Uint8Array(array1.length + array2.length);
  tmp.set(array1, 0);
  tmp.set(array2, array1.length);
  return tmp;
};

Waves.appendNonce = function (originalSeed) {
  var INITIAL_NONCE = 0;
  var nonce = new Uint8Array(converters.int32ToBytes(INITIAL_NONCE, true));

  return Waves.appendUint8Arrays(nonce, originalSeed);
};

Waves.keccakHash = function (messageBytes) {
  return sha3.keccak_256.array(messageBytes);
};

Waves.blake2bHash = function (messageBytes) {
  return blake2b(messageBytes, null, 32);
};

Waves.hashChain = function (noncedSecretPhraseBytes) {
  return Waves.keccakHash(Waves.blake2bHash(new Uint8Array(noncedSecretPhraseBytes)));
};

Waves.sign = function (privateKey, dataToSign) {
  var signatureArrayBuffer = curve25519.sign(privateKey, new Uint8Array(dataToSign));

  return Base58.encode(new Uint8Array(signatureArrayBuffer));
};

Waves.buildAccountSeedHash = function (seedBytes) {
  var data = Waves.appendNonce(seedBytes);
  var seedHash = Waves.hashChain(data);
  var accountSeedHash = SHA256_hash(Array.prototype.slice.call(seedHash), true);

  return new Uint8Array(accountSeedHash);
};

Waves.buildPublicKey = function (seedBytes) {
  var accountSeedHash = Waves.buildAccountSeedHash(seedBytes);
  var p = curve25519.generateKeyPair(new Uint8Array(accountSeedHash.buffer));

  return Base58.encode(new Uint8Array(p.public));
};

Waves.rawPublicKey = function (seedBytes) {
  var accountSeedHash = Waves.buildAccountSeedHash(seedBytes);
  var p = curve25519.generateKeyPair(new Uint8Array(accountSeedHash.buffer));

  return p.public;
};

Waves.buildPrivateKey = function (seedBytes) {
  var accountSeedHash = Waves.buildAccountSeedHash(seedBytes);
  var p = curve25519.generateKeyPair(new Uint8Array(accountSeedHash.buffer));

  return Base58.encode(new Uint8Array(p.private));
};

Waves.shortToByteArray = function (value) {
  return converters.int16ToBytes(value, true);
};

Waves.byteArrayWithSize = function (byteArray) {
  var result = Waves.shortToByteArray(byteArray.length);
  return result.concat(byteArray);
};

Waves.base58StringToByteArray = function (base58String) {
  var decoded = Base58.decode(base58String);
  var result = [];
  for (var i = 0; i < decoded.length; ++i) {
    result.push(decoded[i] & 0xff);
  }

  return result;
};

Waves.buildRawAddress = function (secretPhrase) {

  const publicKeyBytes = this.rawPublicKey(converters.stringToByteArray(secretPhrase));

  if (!publicKeyBytes || publicKeyBytes.length !== 32 || !(publicKeyBytes instanceof Uint8Array)) {
    throw new Error('Missing or invalid public key');
  }

  const prefix = new Uint8Array([1, 'W'.charCodeAt(0)]);
  const publicKeyHashPart = new Uint8Array(this.hashChain(publicKeyBytes).slice(0, 20));

  const rawAddress = this.concatUint8Arrays(prefix, publicKeyHashPart);
  const addressHash = new Uint8Array(this.hashChain(rawAddress).slice(0, 4));

  return Base58.encode(this.concatUint8Arrays(rawAddress, addressHash));

};

Waves.buildRawAddressFromPK = function (publicKey) {

  const publicKeyBytes = new Uint8Array(Base58.decode(publicKey));

  if (!publicKeyBytes || publicKeyBytes.length !== 32 || !(publicKeyBytes instanceof Uint8Array)) {
    throw new Error('Missing or invalid public key');
  }

  const prefix = new Uint8Array([1, 'W'.charCodeAt(0)]);
  const publicKeyHashPart = new Uint8Array(this.hashChain(publicKeyBytes).slice(0, 20));

  const rawAddress = this.concatUint8Arrays(prefix, publicKeyHashPart);
  const addressHash = new Uint8Array(this.hashChain(rawAddress).slice(0, 4));

  return Base58.encode(this.concatUint8Arrays(rawAddress, addressHash));

};

Waves.concatUint8Arrays = function (...args) {

  if (args.length < 2) {
    throw new Error('Two or more Uint8Array are expected');
  }

  if (!(args.every((arg) => arg instanceof Uint8Array))) {
    throw new Error('One of arguments is not a Uint8Array');
  }

  const count = args.length;
  const sumLength = args.reduce((sum, arr) => sum + arr.length, 0);

  const result = new Uint8Array(sumLength);

  let curLength = 0;

  for (let i = 0; i < count; i++) {
    result.set(args[i], curLength);
    curLength += args[i].length;
  }

  return result;

};

Waves.longToByteArray = function (value) {
  var bytes = new Array(7);
  for (var k = 7;k >= 0;k--) {
    bytes[k] = value & (255);
    value /= 256;
  }
  return bytes;
};

Waves.compareAssets = function (asset1, asset2) {
  var first = converters.stringToByteArray(asset1);
  var second = converters.stringToByteArray(asset2);
  var _first = 0;
  var _second = 0;
  first.forEach((byte) => {
    if (!isNaN(byte))
      _first += byte;
  });
  second.forEach((byte) => {
    if (!isNaN(byte))
      _second += byte;
  });

  if (_first < _second) {
    return asset1;
  }
  return asset2;

};

Waves.signatureAssetData = function (senderPublicKey, assetId, feeAssetId, timestamp, amount, fee, recipient, attachment) {
  var transactionType = [4];
  var publicKeyBytes  = Waves.base58StringToByteArray(senderPublicKey);
  var assetIdBytes    = assetId ? [1].concat(Waves.base58StringToByteArray(assetId)) : [0];
  var feeAssetBytes   = feeAssetId ? [1].concat(Waves.base58StringToByteArray(feeAssetId)) : [0];
  var timestampBytes  = Waves.longToByteArray(timestamp);
  var amountBytes     = Waves.longToByteArray(amount);
  var feeBytes        = Waves.longToByteArray(fee);
  var recipientBytes  = Waves.base58StringToByteArray(recipient);
  var attachmentBytes = Waves.byteArrayWithSize(converters.stringToByteArray(attachment));

  return [].concat(transactionType, publicKeyBytes, assetIdBytes, feeAssetBytes, timestampBytes, amountBytes, feeBytes, recipientBytes, attachmentBytes);
};

Waves.signatureDexData = function (senderPublicKey, matcherPublicKey, amountAssetId, priceAssetId, orderType, price, amount, timestamp, expiration, matcherFee) {
  var publicKeyBytes  = Waves.base58StringToByteArray(senderPublicKey);
  var matcherPublicKeyBytes  = Waves.base58StringToByteArray(matcherPublicKey);
  var amountAssetIdBytes    = [1].concat(Waves.base58StringToByteArray(amountAssetId));
  var priceAssetIdBytes    = [1].concat(Waves.base58StringToByteArray(priceAssetId));
  var orderTypeBytes  = [orderType];
  var priceBytes  = Waves.longToByteArray(price);
  var amountBytes  = Waves.longToByteArray(amount);
  var timestampBytes  = Waves.longToByteArray(timestamp);
  var expirationBytes     = Waves.longToByteArray(expiration);
  var matcherFeeBytes        = Waves.longToByteArray(matcherFee);

  return [].concat(publicKeyBytes, matcherPublicKeyBytes, amountAssetIdBytes, priceAssetIdBytes, orderTypeBytes, priceBytes, amountBytes, timestampBytes, expirationBytes, matcherFeeBytes);
};

module.exports = {Waves, converters, blake2b, sha3, SHA256_hash, curve25519, Base58};
