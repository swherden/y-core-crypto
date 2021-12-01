// Nodejs encryption with CTR
const crypto = require("crypto");
const algorithm = "aes-256-cbc";

module.exports.encrypt = function (text, passwd) {
  const iv = crypto.randomBytes(16);
  const key = crypto.scryptSync(passwd, "salt", 32);
  let cipher = crypto.createCipheriv(algorithm, Buffer.from(key), iv);
  let encrypted = cipher.update(text);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return { iv: iv.toString("hex"), encryptedData: encrypted.toString("hex") };
};

module.exports.decrypt = function (encryptedData, _iv, passwd) {
  const key = crypto.scryptSync(passwd, "salt", 32);
  let iv = Buffer.from(_iv, "hex");
  let encryptedText = Buffer.from(encryptedData, "hex");
  let decipher = crypto.createDecipheriv(algorithm, Buffer.from(key), iv);
  let decrypted = decipher.update(encryptedText);
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return decrypted.toString();
};
