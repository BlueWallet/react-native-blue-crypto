import { NativeModules } from 'react-native';

const { BlueCrypto } = NativeModules;

export default BlueCrypto;


module.exports = {

  /**
   * Calculates SCRYPT hash
   *
   * @param passphrase {string} Hex string, for example '717765727479'
   * @param salt {string} Hex string, for example '4749345a22b23cf3'
   * @param N {int}
   * @param r {int}
   * @param p {int}
   * @param dkLen {int}
   * @returns {Promise<string>} Hex string, for example '7DE304E0A42EE837728FB163F54071188FF8EE6D0E40FE6FC1DCF80B48A3ED27'
   */
  scrypt: function(passphrase, salt, N, r, p, dkLen) {
    return new Promise(function (resolve, reject) {
      BlueCrypto.scrypted(passphrase, salt, N, r, p, dkLen, function(result) {
        resolve(result);
      });
    });
  }

};
