# JsWavesKit

JsWavesKit is a JS libraries compilation for encoding/decoding SEED (brainwallet), gettting public/private keys, addresses and preparing transactions for WavesPlatform. Based on [ArkerLabs](https://github.com/ArkerLabs/waves-nodejs) sources, [@waves/waves-api](https://www.npmjs.com/package/@waves/waves-api) and other public software.

##### Web, React Native*, NodeJs ready.

# React Native

For using `crypto` in RN environment you may need to use `rn-nodeify`
([read more](https://stackoverflow.com/questions/29836434/requiring-unknown-module-crypto-in-react-native-environment))

## Installation

Use preferable package manager to install:

```bash
npm install https://github.com/XPGraph/jswaveskit.git
```

## Usage



```js
var Waves = require('@xpgraph/jswaveskit');

var seed = Waves.api.generateNewSeed(15);
console.log('Seed: ' + seed);

var address = Waves.api.getAddress(seed);
console.log('Address: ' + address)

var publicKey = Waves.api.getPublicKey(seed);
console.log('Public key: ' + publicKey);

var password = 'testpassword';

var encrypted = Waves.api.encryptSeedPhrase(seed, password);
console.log('Encrypted seed with "' + password + '" : ' + encrypted);

var decrypted = Waves.api.decryptSeedPhrase(encrypted, password);
console.log('Decrypted seed with "' + password + '" : ' + decrypted);

```
Other helpful methods can be found in waves.api.js (obvious method names)

You can also prepare transactions to be posted to the WavesPlatform

```js
var signedTran = Waves.api.sendAsset(
    assetId,
    seed,
    recipient,
    amount,
    attachment
);

var signedDexOrder = Waves.api.postToDex(
    seed,
    matcherPublicKey,
    asset1,
    asset2,
    orderType,
    price,
    amount,
    fee
);

// for example

const NODEHOST = 'https://nodes.wavesplatform.com/';
const MATCHERHOST = 'https://nodes.wavesplatform.com/matcher';

makeSingleTransaction(signedTran).then((res) => {
    console.log(res);
});

makeDexTransaction(signedDexOrder).then((res) => {
    console.log(res);
});

const makeSingleTransaction = (transaction) => {
    return fetch(`${NODEHOST}/assets/broadcast/transfer`, {
        method: 'POST',
        headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        },
        body: JSON.stringify(transaction)
    }).then((r) => r.json());
};


const makeDexTransaction = (transaction) => {
    return fetch(`${MATCHERHOST}/matcher/orderbook`, {
        method: 'POST',
        headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        },
        body: JSON.stringify(transaction)
    }).then((r) => r.json());
};

```

### Additional Info

See more at [Waves Docs](https://docs.wavesplatform.com/)

## License
[MIT](https://choosealicense.com/licenses/mit/)