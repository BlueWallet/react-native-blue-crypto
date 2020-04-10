import { NativeModules, Platform } from 'react-native';

const { BlueCrypto } = NativeModules;

export default BlueCrypto;


module.exports = {

  isAvailable: function() {
    return typeof navigator !== 'undefined' && navigator.product === 'ReactNative';
  },

  /**
   * Calculates SCRYPT hash
   *
   * @param passphrase {string} Hex string, for example '717765727479' which is 'qwerty'
   * @param salt {string} Hex string, for example '4749345a22b23cf3'
   * @param N {int}
   * @param r {int}
   * @param p {int}
   * @param dkLen {int}
   * @returns {Promise<string>} Hex string, for example '7DE304E0A42EE837728FB163F54071188FF8EE6D0E40FE6FC1DCF80B48A3ED27'
   */
  scrypt: async function(passphrase, salt, N=16384, r=8, p=8, dkLen=32) {
    if (Platform.OS === 'android') {
      return new Promise(function (resolve, reject) {
        BlueCrypto.scrypted(passphrase, salt, N, r, p, dkLen, function (result) {
          resolve(result.toLowerCase());
        });
      });
    } else {
      // for ios passphrase & salt from hex to array of bytes
      const passwd = [];
      for (const pair of Buffer.from(passphrase, 'hex').entries()) {
        passwd.push(pair[1]);
      }

      let slt = [];
      for (const pair of Buffer.from(salt, 'hex').entries()) {
        slt.push(pair[1]);
      }
      return BlueCrypto.scrypt(passwd, slt, N, r, p, dkLen);
    }
  }
};
