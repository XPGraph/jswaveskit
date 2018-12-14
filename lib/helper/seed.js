var dictionary = require('./seed.dictionary');
var secureRandom = require('./secure.random').default;
var converters = require('./converters').default;

var CryptoJS = require('crypto-js');

var { Base58 } = require('../waves');

// const crypto = require('crypto');

const generateNewSeed = (length) => {

  const random = generateRandomUint32Array(length);
  const wordCount = dictionary.length;
  const phrase = [];

  for (let i = 0; i < length; i++) {
    const wordIndex = random[i] % wordCount;
    phrase.push(dictionary[wordIndex]);
  }

  random.set(new Uint8Array(random.length));

  return phrase.join(' ');

};

const getEncodedSeed = (seed) => {

  const seedBytes = converters.stringToByteArray(seed);

  return Base58.encode(seedBytes);

};

const encryptSeedPhrase = (seedPhrase, password, encryptionRounds = 1000) => {

  if (password && password.length < 8) {
    console.log('Your password may be too weak');
  }

  if (encryptionRounds < 1000) {
    console.log('Encryption rounds may be too few');
  }

  if (seedPhrase.length < 15) {
    throw new Error('The seed phrase you are trying to encrypt is too short');
  }

  return encryptSeed(seedPhrase, password, encryptionRounds);
};

const decryptSeedPhrase = (encryptedSeedPhrase, password, encryptionRounds = 1000) => {

  const wrongPasswordMessage = 'The password is wrong';

  let phrase;

  try {
    phrase = decryptSeed(encryptedSeedPhrase, password, encryptionRounds);
  } catch (e) {
    throw new Error(wrongPasswordMessage);
  }

  if (phrase === '' || phrase.length < 15) {
    throw new Error(wrongPasswordMessage);
  }

  return phrase;

};

const encryptSeed = (seed, password, encryptionRounds) => {

  if (!seed || typeof seed !== 'string') {
    throw new Error('Seed is required');
  }

  if (!password || typeof password !== 'string') {
    throw new Error('Password is required');
  }

  password = strengthenPassword(password, encryptionRounds);
  return CryptoJS.AES.encrypt(seed, password).toString();

};

const decryptSeed = (encryptedSeed, password, encryptionRounds) => {

  if (!encryptedSeed || typeof encryptedSeed !== 'string') {
    throw new Error('Encrypted seed is required');
  }

  if (!password || typeof password !== 'string') {
    throw new Error('Password is required');
  }

  password = strengthenPassword(password, encryptionRounds);
  const hexSeed = CryptoJS.AES.decrypt(encryptedSeed, password);
  return converters.hexStringToString(hexSeed.toString());

};

const generateRandomUint32Array = (length) => {

  if (!length || length < 0) {
    throw new Error('Missing or invalid array length');
  }

  const a = secureRandom.randomUint8Array(length);
  const b = secureRandom.randomUint8Array(length);
  const result = new Uint32Array(length);

  for (let i = 0; i < length; i++) {
    const hash = converters.byteArrayToHexString(sha256(`${a[i]}${b[i]}`));
    const randomValue = parseInt(hash.slice(0, 13), 16);
    result.set([randomValue], i);
  }

  return result;

};

const sha256 = (input) => {

  let bytes;
  if (typeof input === 'string') {
    bytes = converters.stringToByteArray(input);
  } else {
    bytes = input;
  }

  const wordArray = converters.byteArrayToWordArrayEx(new Uint8Array(bytes));
  const resultWordArray = CryptoJS.SHA256(wordArray);

  return converters.wordArrayToByteArrayEx(resultWordArray);

};

function strengthenPassword (password, rounds = 5000) {
  while (rounds--) password = converters.byteArrayToHexString(sha256(password));
  return password;
}

module.exports = {
  generateNewSeed,
  getEncodedSeed,
  encryptSeedPhrase,
  decryptSeedPhrase,
};
