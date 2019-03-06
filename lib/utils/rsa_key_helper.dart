import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import "package:asn1lib/asn1lib.dart";
import 'package:flutter/foundation.dart';
import "package:pointycastle/export.dart";

/// Helper class to handle RSA key generation and encoding
class RsaKeyHelper {
  /// Generate a [PublicKey] and [PrivateKey] pair
  ///
  /// Returns a [AsymmetricKeyPair] based on the [RSAKeyGenerator] with custom parameters,
  /// including a [SecureRandom]
  Future<AsymmetricKeyPair<PublicKey, PrivateKey>> computeRSAKeyPair(
      SecureRandom secureRandom) async {
    return await compute(getRsaKeyPair, secureRandom);
  }

  /// Generates a [SecureRandom]
  ///
  /// Returns [FortunaRandom] to be used in the [AsymmetricKeyPair] generation
  SecureRandom getSecureRandom() {
    var secureRandom = FortunaRandom();
    var random = Random.secure();
    List<int> seeds = [];
    for (int i = 0; i < 32; i++) {
      seeds.add(random.nextInt(255));
    }
    secureRandom.seed(new KeyParameter(new Uint8List.fromList(seeds)));
    return secureRandom;
  }

  /// Decode Public key from PEM Format
  ///
  /// Given a base64 encoded PEM [String] with correct headers and footers, return a
  /// [RSAPublicKey]
  ///
  /// *PKCS1*
  /// RSAPublicKey ::= SEQUENCE {
  ///    modulus           INTEGER,  -- n
  ///    publicExponent    INTEGER   -- e
  /// }
  ///
  /// *PKCS8*
  /// PublicKeyInfo ::= SEQUENCE {
  ///   algorithm       AlgorithmIdentifier,
  ///   PublicKey       BIT STRING
  /// }
  ///
  /// AlgorithmIdentifier ::= SEQUENCE {
  ///   algorithm       OBJECT IDENTIFIER,
  ///   parameters      ANY DEFINED BY algorithm OPTIONAL
  /// }
  RSAPublicKey parsePublicKeyFromPem(pemString) {
    List<int> publicKeyDER = decodePEM(pemString);
    var asn1Parser = new ASN1Parser(publicKeyDER);
    var topLevelSeq = asn1Parser.nextObject() as ASN1Sequence;

    var modulus, exponent;
    // Depending on the first element type, we either have PKCS1 or 2
    if (topLevelSeq.elements[0].runtimeType == ASN1Integer) {
      modulus = topLevelSeq.elements[0] as ASN1Integer;
      exponent = topLevelSeq.elements[1] as ASN1Integer;
    } else {
      var publicKeyBitString = topLevelSeq.elements[1];

      var publicKeyAsn = new ASN1Parser(publicKeyBitString.contentBytes());
      ASN1Sequence publicKeySeq = publicKeyAsn.nextObject();
      modulus = publicKeySeq.elements[0] as ASN1Integer;
      exponent = publicKeySeq.elements[1] as ASN1Integer;
    }

    RSAPublicKey rsaPublicKey =
        RSAPublicKey(modulus.valueAsBigInteger, exponent.valueAsBigInteger);

    return rsaPublicKey;
  }

  /// Sign plain text with Private Key
  ///
  /// Given a plain text [String] and a [RSAPrivateKey], decrypt the text using
  /// a [RSAEngine] cipher
  String sign(String plainText, RSAPrivateKey privateKey) {
    var signer = RSASigner(SHA256Digest(), "0609608648016503040201");
    signer.init(true, PrivateKeyParameter<RSAPrivateKey>(privateKey));
    return  base64Encode(signer.generateSignature(createUint8ListFromString(plainText)).bytes);
  }


  /// Creates a [Uint8List] from a string to be signed
  Uint8List createUint8ListFromString(String s) {
    var codec = Utf8Codec(allowMalformed: true);
    return Uint8List.fromList(codec.encode(s));
  }

  /// Decode Private key from PEM Format
  ///
  /// Given a base64 encoded PEM [String] with correct headers and footers, return a
  /// [RSAPrivateKey]
  RSAPrivateKey parsePrivateKeyFromPem(pemString) {
    List<int> privateKeyDER = decodePEM(pemString);
    var asn1Parser = new ASN1Parser(privateKeyDER);
    var topLevelSeq = asn1Parser.nextObject() as ASN1Sequence;

    var modulus, privateExponent, p, q;
    // Depending on the number of elements, we will either use PKCS1 or PKCS8
    if (topLevelSeq.elements.length == 3) {
      var privateKey = topLevelSeq.elements[2];

      asn1Parser = new ASN1Parser(privateKey.contentBytes());
      var pkSeq = asn1Parser.nextObject() as ASN1Sequence;

      modulus = pkSeq.elements[1] as ASN1Integer;
      privateExponent = pkSeq.elements[3] as ASN1Integer;
      p = pkSeq.elements[4] as ASN1Integer;
      q = pkSeq.elements[5] as ASN1Integer;
    } else {
      modulus = topLevelSeq.elements[1] as ASN1Integer;
      privateExponent = topLevelSeq.elements[3] as ASN1Integer;
      p = topLevelSeq.elements[4] as ASN1Integer;
      q = topLevelSeq.elements[5] as ASN1Integer;
    }

    RSAPrivateKey rsaPrivateKey = RSAPrivateKey(
        modulus.valueAsBigInteger,
        privateExponent.valueAsBigInteger,
        p.valueAsBigInteger,
        q.valueAsBigInteger);

    return rsaPrivateKey;
  }

  List<int> decodePEM(String pem) {
    return base64.decode(removePemHeaderAndFooter(pem));
  }

  String removePemHeaderAndFooter(String pem) {
    var startsWith = [
      "-----BEGIN PUBLIC KEY-----",
      "-----BEGIN RSA PRIVATE KEY-----",
      "-----BEGIN RSA PUBLIC KEY-----",
      "-----BEGIN PRIVATE KEY-----",
      "-----BEGIN PGP PUBLIC KEY BLOCK-----\r\nVersion: React-Native-OpenPGP.js 0.1\r\nComment: http://openpgpjs.org\r\n\r\n",
      "-----BEGIN PGP PRIVATE KEY BLOCK-----\r\nVersion: React-Native-OpenPGP.js 0.1\r\nComment: http://openpgpjs.org\r\n\r\n",
    ];
    var endsWith = [
      "-----END PUBLIC KEY-----",
      "-----END PRIVATE KEY-----",
      "-----END RSA PRIVATE KEY-----",
      "-----END RSA PUBLIC KEY-----",
      "-----END PGP PUBLIC KEY BLOCK-----",
      "-----END PGP PRIVATE KEY BLOCK-----",
    ];
    bool isOpenPgp = pem.indexOf('BEGIN PGP') != -1;

    pem = pem.replaceAll(' ', '');
    pem = pem.replaceAll('\n', '');
    pem = pem.replaceAll('\r', '');

    for (var s in startsWith) {
      s = s.replaceAll(' ', '');
      if (pem.startsWith(s)) {
        pem = pem.substring(s.length);
      }
    }

    for (var s in endsWith) {
      s = s.replaceAll(' ', '');
      if (pem.endsWith(s)) {
        pem = pem.substring(0, pem.length - s.length);
      }
    }

    if (isOpenPgp) {
      var index = pem.indexOf('\r\n');
      pem = pem.substring(0, index);
    }

    return pem;
  }

  /// Encode Private key to PEM Format
  ///
  /// Given [RSAPrivateKey] returns a base64 encoded [String] with standard PEM headers and footers
  String encodePrivateKeyToPemPKCS1(RSAPrivateKey privateKey) {

    var topLevel = new ASN1Sequence();

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

    return """-----BEGIN PRIVATE KEY-----\r\n$dataBase64\r\n-----END PRIVATE KEY-----""";
  }

  /// Encode Public key to PEM Format
  ///
  /// Given [RSAPublicKey] returns a base64 encoded [String] with standard PEM headers and footers
  String encodePublicKeyToPemPKCS1(RSAPublicKey publicKey) {
    var topLevel = new ASN1Sequence();

    topLevel.add(ASN1Integer(publicKey.modulus));
    topLevel.add(ASN1Integer(publicKey.exponent));

    var dataBase64 = base64.encode(topLevel.encodedBytes);
    return """-----BEGIN PUBLIC KEY-----\r\n$dataBase64\r\n-----END PUBLIC KEY-----""";
  }
}

/// Generate a [PublicKey] and [PrivateKey] pair
///
/// Returns a [AsymmetricKeyPair] based on the [RSAKeyGenerator] with custom parameters,
/// including a [SecureRandom]
AsymmetricKeyPair<PublicKey, PrivateKey> getRsaKeyPair(
    SecureRandom secureRandom) {
  var rsapars = new RSAKeyGeneratorParameters(BigInt.from(65537), 2048, 5);
  var params = new ParametersWithRandom(rsapars, secureRandom);
  var keyGenerator = new RSAKeyGenerator();
  keyGenerator.init(params);
  return keyGenerator.generateKeyPair();
}
