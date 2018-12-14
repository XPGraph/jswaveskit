var Waves = require('../lib/waves.api.js');

var seed = Waves.api.generateNewSeed(15);
console.log('Seed: ' + seed);

var address = Waves.api.getAddress(seed);
console.log('Address: ' + address)

var publicKey = Waves.api.getPublicKey(seed);
console.log('Public key: ' + publicKey);

var password = 'test_password';

var encrypted = Waves.api.encryptSeedPhrase(seed, password);
console.log('Encrypted seed with "' + password + '" : ' + encrypted);

var decrypted = Waves.api.decryptSeedPhrase(encrypted, password);
console.log('Decrypted seed with "' + password + '" : ' + decrypted);