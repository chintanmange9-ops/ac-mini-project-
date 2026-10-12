/* crypto.js — THE ONLY frontend file that knows HOW encryption works.
 * All pages call CryptoProvider.encryptField / decryptField / sha256
 * and never touch CryptoJS directly.
 * To change encryption in future: replace ONLY this object + keep the
 * same 4 function names. Backend config.ENCRYPTION_ALGO must match.
 */
const CryptoProvider = (() => {
  const ALGO = "AES-256-CBC";
  const KEY_VERSION = 1;
  // MUST match config.py DEMO_KEY. Demo only — visible in JS by design for viva.
  const DEMO_KEY = "0123456789abcdef0123456789abcdef";

  function _key() { return CryptoJS.enc.Utf8.parse(DEMO_KEY); }

  function randomIV() {
    return CryptoJS.lib.WordArray.random(16).toString(CryptoJS.enc.Base64);
  }

  // plaintext -> base64 ciphertext (CBC with given base64 IV)
  function encryptField(plaintext, ivB64) {
    const iv = CryptoJS.enc.Base64.parse(ivB64);
    const enc = CryptoJS.AES.encrypt(plaintext, _key(), { iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
    return CryptoJS.enc.Base64.stringify(enc.ciphertext);
  }

  // base64 ciphertext -> plaintext
  function decryptField(cipherB64, ivB64) {
    const iv = CryptoJS.enc.Base64.parse(ivB64);
    const ct = CryptoJS.enc.Base64.parse(cipherB64);
    const params = CryptoJS.lib.CipherParams.create({ ciphertext: ct });
    const dec = CryptoJS.AES.decrypt(params, _key(), { iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
    return dec.toString(CryptoJS.enc.Utf8);
  }

  // fingerprint (one-way, cannot unlock)
  function sha256(text) {
    return CryptoJS.SHA256(text).toString(CryptoJS.enc.Hex);
  }

  return { ALGO, KEY_VERSION, randomIV, encryptField, decryptField, sha256 };
})();
