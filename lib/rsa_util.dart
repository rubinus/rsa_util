library rsa_util;

import 'package:pointycastle/pointycastle.dart';
import 'dart:convert';
import 'dart:typed_data';
import 'package:asn1lib/asn1lib.dart';
import 'fixed_secure_random.dart';

class RSAUtil {

  static RSAPublicKey publicKey;

  static RSAPrivateKey privateKey;

  static RSAUtil instance;

  ///单例
  static RSAUtil getInstance(String publicKeyFile, String privateKeyFile) {
    if (instance == null) {
      instance = RSAUtil(publicKeyFile, privateKeyFile);
    }
    return instance;
  }

  ///保证PEM证书只被解析一次
  RSAUtil(String publicKeyFile, String privateKeyFile) {
    if (publicKeyFile != null) {
      publicKey = parse(publicKeyFile);
    }
    if (privateKeyFile != null) {
      privateKey = parse(privateKeyFile);
    }
  }

  ///生成公匙 和 私匙，默认1024，u can input 128,256,512,1024,2048
  static List<String> generateKeys ([int bits = 1024]){
    var rnd = FixedSecureRandom();
    var rsapars = RSAKeyGeneratorParameters(BigInt.parse("65537"), bits, 12);
    var params = ParametersWithRandom(rsapars, rnd);

    var keyGenerator = KeyGenerator("RSA");
    keyGenerator.init(params);

    AsymmetricKeyPair<PublicKey, PrivateKey> keyPair =
    keyGenerator.generateKeyPair();
    RSAPrivateKey privateKey = keyPair.privateKey;
    RSAPublicKey publicKey = keyPair.publicKey;

    var pubKey = encodePublicKeyToPemPKCS1(publicKey);

    var priKey = encodePrivateKeyToPemPKCS1(privateKey);

    return [pubKey, priKey];
  }

  ///RSA公钥加密
  encryptByPublicKey(String data) {
    try {
      var keyParameter = () => PublicKeyParameter<RSAPublicKey>(publicKey);
//      var keyParameter = () => PrivateKeyParameter<RSAPrivateKey>(privateKey);
      AsymmetricBlockCipher cipher = AsymmetricBlockCipher("RSA/PKCS1");
      cipher.reset();
      cipher.init(true, keyParameter());
      Uint8List encryptResult = cipher.process(utf8.encode(data));
      String encrypted = Base64Encoder().convert(encryptResult);

      return encrypted;
    } catch (e) {
      print(e.toString());
    }
  }
  ///RSA私钥加密
  encryptByPrivateKey(String data) {
    try {
//      var keyParameter = () => PublicKeyParameter<RSAPublicKey>(publicKey);
      var keyParameter = () => PrivateKeyParameter<RSAPrivateKey>(privateKey);
      AsymmetricBlockCipher cipher = AsymmetricBlockCipher("RSA/PKCS1");
      cipher.reset();
      cipher.init(true, keyParameter());
      Uint8List encryptResult = cipher.process(utf8.encode(data));
      String encrypted = Base64Encoder().convert(encryptResult);

      return encrypted;
    } catch (e) {
      print(e.toString());
    }
  }

  ///RSA公钥解密
  decryptByPublicKey(String data) {
    try {
//      var keyParameter = () => PrivateKeyParameter<RSAPrivateKey>(privateKey);
      var keyParameter = () => PublicKeyParameter<RSAPublicKey>(publicKey);
      AsymmetricBlockCipher cipher = AsymmetricBlockCipher("RSA/PKCS1");
      cipher.reset();
      cipher.init(false, keyParameter());
      Uint8List bconv = Base64Decoder().convert(data);
      final decrypted = cipher.process(bconv);
      String res = String.fromCharCodes(decrypted);
      return res;
    } catch (e) {
      print(e.toString());
    }
  }

  ///RSA私钥解密
  decryptByPrivateKey(String data) {
    try {
      var keyParameter = () => PrivateKeyParameter<RSAPrivateKey>(privateKey);
//      var keyParameter = () => PublicKeyParameter<RSAPublicKey>(publicKey);
      AsymmetricBlockCipher cipher = AsymmetricBlockCipher("RSA/PKCS1");
      cipher.reset();
      cipher.init(false, keyParameter());
      Uint8List bconv = Base64Decoder().convert(data);
      final decrypted = cipher.process(bconv);
      String res = String.fromCharCodes(decrypted);
      return res;
    } catch (e) {
      print(e.toString());
    }
  }


  static String encodePublicKeyToPemPKCS1(RSAPublicKey publicKey) {
    var topLevel = ASN1Sequence();

    topLevel.add(ASN1Integer(publicKey.modulus));
    topLevel.add(ASN1Integer(publicKey.exponent));

    var dataBase64 = base64.encode(topLevel.encodedBytes);
    return """-----BEGIN RSA PUBLIC KEY-----\n$dataBase64\n-----END RSA PUBLIC KEY-----""";
//  return dataBase64;
  }

  static String encodePrivateKeyToPemPKCS1(RSAPrivateKey privateKey) {
    var topLevel = ASN1Sequence();

    var version = ASN1Integer(BigInt.from(0));
    var modulus = ASN1Integer(privateKey.n);
    var publicExponent = ASN1Integer(privateKey.exponent);
    var privateExponent = ASN1Integer(privateKey.d);
    var p = ASN1Integer(privateKey.p);
    var q = ASN1Integer(privateKey.q);
    var dP = privateKey.d % (privateKey.p - BigInt.from(1));
    var exp1 = ASN1Integer(dP);
    var dQ = privateKey.d % (privateKey.q - BigInt.from(1));
    var exp2 = ASN1Integer(dQ);
    var iQ = privateKey.q.modInverse(privateKey.p);
    var co = ASN1Integer(iQ);

    topLevel.add(version);
    topLevel.add(modulus);
    topLevel.add(publicExponent);
    topLevel.add(privateExponent);
    topLevel.add(p);
    topLevel.add(q);
    topLevel.add(exp1);
    topLevel.add(exp2);
    topLevel.add(co);

    var dataBase64 = base64.encode(topLevel.encodedBytes);

    return """-----BEGIN RSA PRIVATE KEY-----\n$dataBase64\n-----END RSA PRIVATE KEY-----""";
//  return dataBase64;
  }


  ///解析PEM证书生成RSA密钥
  RSAAsymmetricKey parse(String key) {
    final rows = key.split('\n'); // LF-only, this could be a problem
    final header = rows.first;
    if (header == '-----BEGIN RSA PUBLIC KEY-----') {
      return _parsePublic(_parseSequence(rows));
    }

    if (header == '-----BEGIN PUBLIC KEY-----') {
      return _parsePublic(_pkcs8PublicSequence(_parseSequence(rows)));
    }

    if (header == '-----BEGIN RSA PRIVATE KEY-----') {
      return _parsePrivate(_parseSequence(rows));
    }

    if (header == '-----BEGIN PRIVATE KEY-----') {
      return _parsePrivate(_pkcs8PrivateSequence(_parseSequence(rows)));
    }
    // NOTE: Should we throw an exception?
    return null;
  }

  RSAAsymmetricKey _parsePublic(ASN1Sequence sequence) {
    final modulus = (sequence.elements[0] as ASN1Integer).valueAsBigInteger;
    final exponent = (sequence.elements[1] as ASN1Integer).valueAsBigInteger;

    return RSAPublicKey(modulus, exponent);
  }

  RSAAsymmetricKey _parsePrivate(ASN1Sequence sequence) {
    final modulus = (sequence.elements[1] as ASN1Integer).valueAsBigInteger;
    final exponent = (sequence.elements[3] as ASN1Integer).valueAsBigInteger;
    final p = (sequence.elements[4] as ASN1Integer).valueAsBigInteger;
    final q = (sequence.elements[5] as ASN1Integer).valueAsBigInteger;

    return RSAPrivateKey(modulus, exponent, p, q);
  }

  ASN1Sequence _parseSequence(List<String> rows) {
    final keyText = rows
        .skipWhile((row) => row.startsWith('-----BEGIN'))
        .takeWhile((row) => !row.startsWith('-----END'))
        .map((row) => row.trim())
        .join('');

    final keyBytes = Uint8List.fromList(base64.decode(keyText));
    final asn1Parser = ASN1Parser(keyBytes);

    return asn1Parser.nextObject() as ASN1Sequence;
  }

  ASN1Sequence _pkcs8PublicSequence(ASN1Sequence sequence) {
    final ASN1BitString bitString = sequence.elements[1];
    final bytes = bitString.valueBytes().sublist(1);
    final parser = ASN1Parser(Uint8List.fromList(bytes));

    return parser.nextObject() as ASN1Sequence;
  }

  ASN1Sequence _pkcs8PrivateSequence(ASN1Sequence sequence) {
    final ASN1BitString bitString = sequence.elements[2];
    final bytes = bitString.valueBytes();
    final parser = ASN1Parser(bytes);

    return parser.nextObject() as ASN1Sequence;
  }

}