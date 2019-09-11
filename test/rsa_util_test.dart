import 'package:flutter_test/flutter_test.dart';

import 'package:rsa_util/rsa_util.dart';

const s = "This is a test by RSA 123456 !"; //the s length limit 127

void main() {
  test('adds one to input values', () {
    List<String> keys = RSAUtil.generateKeys(1024);
    final String pubKey = keys[0];
    final String priKey = keys[1];

    RSAUtil rsa = RSAUtil.getInstance(pubKey, priKey);

    var jiami = rsa.encryptByPublicKey(s);
    print("公匙加密" + jiami);

    var jiemi = rsa.decryptByPrivateKey(jiami);
    print("私匙解密" + jiemi);

    var jiami2 = rsa.encryptByPrivateKey(s);
    print("私匙加密" + jiami2);

    var jiemi2 = rsa.decryptByPublicKey(jiami2);
    print("公匙解密" + jiemi2);

  });
}
