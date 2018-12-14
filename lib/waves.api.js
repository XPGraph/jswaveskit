var { Waves, converters, curve25519, Base58 } = require('./waves');
var { generateNewSeed, encryptSeedPhrase, decryptSeedPhrase, getEncodedSeed } = require('./helper/seed');
var secureRandom = require('./helper/secure.random');

Waves.api = {};

Waves.api.getAddressFromPK = function (publicKey) {
  return Waves.buildRawAddressFromPK(publicKey);
};

Waves.api.generateNewSeed = function (length) {
  return generateNewSeed(length);
};

Waves.api.getAddress = function (seed) {
  return Waves.buildRawAddress(seed);
};

Waves.api.getPublicKey = function (seed) {
  return Waves.getPublicKey(seed);
};

Waves.api.getPrivateKey = function (seed) {
  return Waves.getPrivateKey(seed);
};

Waves.api.getEncodedSeed = function (seed) {
  return getEncodedSeed(seed);
};

Waves.api.encryptSeedPhrase = function (seed, password) {
  return encryptSeedPhrase(seed, password);
};

Waves.api.decryptSeedPhrase = function (seed, password) {
  return decryptSeedPhrase(seed, password);
};

Waves.api.sendAsset = function (assetId, seed, recipient, amount, attachment = '') {
    var timestamp = Date.now();
    var transferData = {
      'senderPublicKey': Waves.getPublicKey(seed),
      assetId,
      timestamp,
      amount,
      'fee': 100000,
      recipient,
      attachment,
    };

    var dataToSign = Waves.signatureAssetData(
      transferData.senderPublicKey,
      transferData.assetId,
      null,
      transferData.timestamp,
      transferData.amount,
      transferData.fee,
      transferData.recipient,
      transferData.attachment
    );
    var privateKeyBytes = Base58.decode(Waves.getPrivateKey(seed));
    var buf = secureRandom.randomUint8Array(64);
    var signature = Base58.encode(curve25519.sign(privateKeyBytes, new Uint8Array(dataToSign), buf));
    var dataToSend = transferData;
    dataToSend.attachment = Base58.encode(converters.stringToByteArray(attachment));
    dataToSend.signature = signature;

    return dataToSend;
};

Waves.api.compareAssets = function (asset1, asset2) {
  return Waves.compareAssets(asset1, asset2);
};

Waves.api.postToDex = function (seed, matcherPublicKey, asset1, asset2, orderType, price, amount, fee) {
    var timestamp = Date.now();

    var otype = orderType === 'buy' ? 0 : 1;

    var dexData = {
      'senderPublicKey': Waves.getPublicKey(seed),
      matcherPublicKey,
      'amountAssetId': asset1,
      'priceAssetId': asset2,
      'orderType': otype,
      price,
      amount,
      timestamp,
      'expiration': timestamp + 10 * 86400000,
      'matcherFee': fee,
    };

    var json = {
      'senderPublicKey': Waves.getPublicKey(seed),
      matcherPublicKey,
      'assetPair': {
        'amountAsset': asset1,
        'priceAsset': asset2,
      },
      orderType,
      price,
      amount,
      timestamp,
      'expiration': timestamp + 10 * 86400000,
      'matcherFee': fee,
    };

    var dataToSign = Waves.signatureDexData(
      dexData.senderPublicKey,
      dexData.matcherPublicKey,
      dexData.amountAssetId,
      dexData.priceAssetId,
      dexData.orderType,
      dexData.price,
      dexData.amount,
      dexData.timestamp,
      dexData.expiration,
      dexData.matcherFee
    );
    var privateKeyBytes = Base58.decode(Waves.getPrivateKey(seed));

    var buf = secureRandom.randomUint8Array(64);
    var signature = Base58.encode(curve25519.sign(privateKeyBytes, new Uint8Array(dataToSign), buf));
    var dataToSend = json;
    dataToSend.signature = signature;

    return dataToSend;
};

module.exports = Waves;
