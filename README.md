# react-native-blue-crypto

## Getting started

`$ npm install https://github.com/Overtorment/react-native-blue-crypto --save`

## Usage
```javascript
  const bluecrypto = require("react-native-blue-crypto");
  const hash = await bluecrypto.scrypt('022413a674b5bceab5abe0b14ce44dfa7fc6b55ecdbed88e7c50c0b4e953f1e05e', '059a548167010a9573418906');
```

## Based on 
* [jhash](https://github.com/amdelamar/jhash) (c) Austin Delamar, under the Apache-2.0/BSD-2-Clause license
* [libscrypt](https://github.com/technion/libscrypt) (c) 2013, Joshua Small under the BSD license
* [react-native-scrypt](https://github.com/Crypho/react-native-scrypt) by Yiorgis Gozadinos (c) 2017 Crypho AS under The MIT License

## License

MIT
