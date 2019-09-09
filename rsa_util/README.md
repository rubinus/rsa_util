# rsa_util

rsa util

## Getting Started

void main() {


  const s = "This is a test by RSA 123456 !"; //the s length limit 127

  List<String> keys = RSAUtil.generateKeys(1024);
  final String pubKey = keys[0];
  final String priKey = keys[1];

  RSAUtil rsa = RSAUtil.getInstance(pubKey, priKey);

  var jiami = rsa.encryptByPublicKey(s);
  print("公匙加密" + jiami);

  var jiemi = rsa.decryptByPrivateKey(jiami);
  print("私匙解密" + jiemi);

  var jiami2 = rsa.encryptByPublicKey(s);
  print("私匙加密" + jiami2);

  var jiemi2 = rsa.decryptByPrivateKey(jiami);
  print("公匙解密" + jiemi2);

}
