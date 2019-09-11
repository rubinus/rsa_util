import 'package:rsa_util/rsa_util.dart';

void main(){

  const s = "This is a sss test by RSA 123456 !"; //the s length limit 117

  //如果你没有密匙，你可以生成一个，像下面这样，生成1024位的公匙和私匙
  List<String> keys = RSAUtil.generateKeys(1024);
  final String pubKey = keys[0];
  final String priKey = keys[1];

  //如果你有密匙，你可以直接调用下面这个方法
  RSAUtil rsa = RSAUtil.getInstance(pubKey, priKey);

  var jiami = rsa.encryptByPublicKey(s);
  print("公匙加密" + jiami);

  var jiemi = rsa.decryptByPrivateKey(jiami);
  print("私匙解密" + jiemi);

  var jiami2 = rsa.encryptByPrivateKey(s);
  print("私匙加密" + jiami2);

  var jiemi2 = rsa.decryptByPublicKey(jiami2);
  print("公匙解密" + jiemi2);

}