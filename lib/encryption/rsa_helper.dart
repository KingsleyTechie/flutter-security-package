import 'dart:convert';
import 'dart:typed_data';
import 'package:pointycastle/export.dart';
import 'package:encrypt/encrypt.dart';
import '../security_manager.dart';

class RSAHelper {
  static final RSAHelper _instance = RSAHelper._internal();
  factory RSAHelper() => _instance;
  RSAHelper._internal();
  
  static bool _isInitialized = false;
  static AsymmetricKeyPair<PublicKey, PrivateKey>? _keyPair;
  static PublicKey? _publicKey;
  static PrivateKey? _privateKey;
  
  Future<void> initialize({int keySize = 2048}) async {
    if (_isInitialized) {
      throw SecurityException('RSAHelper already initialized');
    }
    
    try {
      // Generate RSA key pair
      _keyPair = await _generateRSAKeyPair(keySize);
      _publicKey = _keyPair!.publicKey;
      _privateKey = _keyPair!.privateKey;
      
      _isInitialized = true;
      
      SecurityManager()._logSecurityEvent(
        SecurityEvent(
          type: SecurityEventType.initialized,
          severity: SecuritySeverity.info,
          message: 'RSAHelper initialized with $keySize-bit key',
          timestamp: DateTime.now(),
        ),
      );
    } catch (e) {
      SecurityManager()._logSecurityEvent(
        SecurityEvent(
          type: SecurityEventType.encryptionError,
          severity: SecuritySeverity.critical,
          message: 'Failed to initialize RSAHelper: $e',
          timestamp: DateTime.now(),
        ),
      );
      rethrow;
    }
  }
  
  Future<String> encryptWithPublicKey(String plaintext, String publicKeyPem) async {
    try {
      final publicKey = _parsePublicKeyFromPem(publicKeyPem);
      final encryptor = OAEPEncoding(RSAEngine())
        ..init(true, PublicKeyParameter<RSAPublicKey>(publicKey));
      
      final plaintextBytes = utf8.encode(plaintext);
      final encryptedBytes = encryptor.process(plaintextBytes);
      
      return base64.encode(encryptedBytes);
    } catch (e) {
      SecurityManager()._logSecurityEvent(
        SecurityEvent(
          type: SecurityEventType.encryptionError,
          severity: SecuritySeverity.high,
          message: 'RSA encryption failed: $e',
          timestamp: DateTime.now(),
        ),
      );
      throw SecurityException('RSA encryption failed');
    }
  }
  
  Future<String> decryptWithPrivateKey(String encryptedBase64) async {
    if (!_isInitialized) {
      await initialize();
    }
    
    try {
      final decryptor = OAEPEncoding(RSAEngine())
        ..init(false, PrivateKeyParameter<RSAPrivateKey>(_privateKey as RSAPrivateKey));
      
      final encryptedBytes = base64.decode(encryptedBase64);
      final decryptedBytes = decryptor.process(encryptedBytes);
      
      return utf8.decode(decryptedBytes);
    } catch (e) {
      SecurityManager()._logSecurityEvent(
        SecurityEvent(
          type: SecurityEventType.decryptionError,
          severity: SecuritySeverity.high,
          message: 'RSA decryption failed: $e',
          timestamp: DateTime.now(),
        ),
      );
      throw SecurityException('RSA decryption failed');
    }
  }
  
  Future<String> signData(String data) async {
    if (!_isInitialized) {
      await initialize();
    }
    
    try {
      final signer = RSASigner(SHA256Digest(), '0609608648016503040201');
      signer.init(true, PrivateKeyParameter<RSAPrivateKey>(_privateKey as RSAPrivateKey));
      
      final dataBytes = utf8.encode(data);
      final signature = signer.generateSignature(Uint8List.fromList(dataBytes));
      
      return base64.encode(signature.bytes);
    } catch (e) {
      SecurityManager()._logSecurityEvent(
        SecurityEvent(
          type: SecurityEventType.encryptionError,
          severity: SecuritySeverity.high,
          message: 'Data signing failed: $e',
          timestamp: DateTime.now(),
        ),
      );
      throw SecurityException('Data signing failed');
    }
  }
  
  Future<bool> verifySignature(String data, String signatureBase64, String publicKeyPem) async {
    try {
      final publicKey = _parsePublicKeyFromPem(publicKeyPem);
      final verifier = RSASigner(SHA256Digest(), '0609608648016503040201');
      verifier.init(false, PublicKeyParameter<RSAPublicKey>(publicKey));
      
      final dataBytes = utf8.encode(data);
      final signatureBytes = base64.decode(signatureBase64);
      final signature = Signature(signatureBytes, null);
      
      return verifier.verifySignature(
        Uint8List.fromList(dataBytes),
        signature,
      );
    } catch (e) {
      SecurityManager()._logSecurityEvent(
        SecurityEvent(
          type: SecurityEventType.encryptionError,
          severity: SecuritySeverity.high,
          message: 'Signature verification failed: $e',
          timestamp: DateTime.now(),
        ),
      );
      return false;
    }
  }
  
  String getPublicKeyPem() {
    if (!_isInitialized) {
      throw SecurityException('RSAHelper not initialized');
    }
    
    final publicKey = _publicKey as RSAPublicKey;
    final modulus = publicKey.modulus;
    final exponent = publicKey.exponent;
    
    // Convert to PEM format
    final sequence = ASN1Sequence();
    sequence.add(ASN1Integer(modulus));
    sequence.add(ASN1Integer(exponent));
    
    final publicKeyASN1 = ASN1Sequence();
    publicKeyASN1.add(ASN1Sequence()
      ..add(ASN1ObjectIdentifier.fromComponentString('1.2.840.113549.1.1.1'))
      ..add(ASN1Null()));
    publicKeyASN1.add(ASN1BitString(sequence.encodedBytes));
    
    final base64Key = base64.encode(publicKeyASN1.encodedBytes);
    final pem = '-----BEGIN PUBLIC KEY-----\n'
        '${_splitPem(base64Key)}\n'
        '-----END PUBLIC KEY-----';
    
    return pem;
  }
  
  String getPrivateKeyPem() {
    if (!_isInitialized) {
      throw SecurityException('RSAHelper not initialized');
    }
    
    // Note: In production, private key should never leave secure storage
    // This is for demonstration only
    final privateKey = _privateKey as RSAPrivateKey;
    
    // Convert to PEM format (simplified)
    final base64Key = base64.encode(_privateKeyToBytes(privateKey));
    final pem = '-----BEGIN PRIVATE KEY-----\n'
        '${_splitPem(base64Key)}\n'
        '-----END PRIVATE KEY-----';
    
    return pem;
  }
  
  Future<Uint8List> encryptFile(Uint8List fileData, String publicKeyPem) async {
    try {
      // RSA is slow for large data, so encrypt with AES first
      final aesKey = await AESEncryption()._generateSecureKey();
      final aesEncrypted = await AESEncryption.encryptData(
        fileData,
        key: base64.encode(aesKey.bytes),
      );
      
      // Encrypt AES key with RSA
      final encryptedAesKey = await encryptWithPublicKey(
        base64.encode(aesKey.bytes),
        publicKeyPem,
      );
      
      // Combine encrypted key and data
      final result = Uint8List(4 + encryptedAesKey.length + aesEncrypted.length);
      
      // Write key length (4 bytes)
      final keyLength = encryptedAesKey.length;
      result[0] = (keyLength >> 24) & 0xFF;
      result[1] = (keyLength >> 16) & 0xFF;
      result[2] = (keyLength >> 8) & 0xFF;
      result[3] = keyLength & 0xFF;
      
      // Write encrypted key
      final keyBytes = utf8.encode(encryptedAesKey);
      result.setAll(4, keyBytes);
      
      // Write encrypted data
      result.setAll(4 + keyBytes.length, aesEncrypted);
      
      return result;
    } catch (e) {
      SecurityManager()._logSecurityEvent(
        SecurityEvent(
          type: SecurityEventType.encryptionError,
          severity: SecuritySeverity.high,
          message: 'File encryption failed: $e',
          timestamp: DateTime.now(),
        ),
      );
      throw SecurityException('File encryption failed');
    }
  }
  
  Future<Uint8List> decryptFile(Uint8List encryptedData) async {
    if (!_isInitialized) {
      await initialize();
    }
    
    try {
      // Extract key length
      final keyLength = (encryptedData[0] << 24) |
          (encryptedData[1] << 16) |
          (encryptedData[2] << 8) |
          encryptedData[3];
      
      // Extract encrypted AES key
      final encryptedKeyBytes = encryptedData.sublist(4, 4 + keyLength);
      final encryptedKey = utf8.decode(encryptedKeyBytes);
      
      // Decrypt AES key
      final aesKeyBase64 = await decryptWithPrivateKey(encryptedKey);
      final aesKey = base64.decode(aesKeyBase64);
      
      // Extract encrypted data
      final encryptedFileData = encryptedData.sublist(4 + keyLength);
      
      // Decrypt data with AES
      final decryptedData = await AESEncryption.decryptData(
        encryptedFileData,
        key: base64.encode(aesKey),
      );
      
      return decryptedData;
    } catch (e) {
      SecurityManager()._logSecurityEvent(
        SecurityEvent(
          type: SecurityEventType.decryptionError,
          severity: SecuritySeverity.high,
          message: 'File decryption failed: $e',
          timestamp: DateTime.now(),
        ),
      );
      throw SecurityException('File decryption failed');
    }
  }
  
  Future<AsymmetricKeyPair<PublicKey, PrivateKey>> _generateRSAKeyPair(int keySize) async {
    final keyParams = RSAKeyGeneratorParameters(
      BigInt.parse('65537'),
      keySize,
      64,
    );
    
    final random = SecureRandom('Fortuna')
      ..seed(KeyParameter(Uint8List.fromList(List.generate(32, (i) => i))));
    
    final generator = RSAKeyGenerator();
    generator.init(ParametersWithRandom(keyParams, random));
    
    return generator.generateKeyPair();
  }
  
  RSAPublicKey _parsePublicKeyFromPem(String pem) {
    // Remove PEM headers and newlines
    final lines = pem.split('\n');
    var base64Data = '';
    
    for (final line in lines) {
      if (!line.startsWith('-----')) {
        base64Data += line;
      }
    }
    
    final bytes = base64.decode(base64Data);
    final asn1Parser = ASN1Parser(bytes);
    final topLevelSeq = asn1Parser.nextObject() as ASN1Sequence;
    final publicKeySeq = topLevelSeq.elements[1] as ASN1Sequence;
    final bitString = publicKeySeq.elements[0] as ASN1BitString;
    
    final keyAsn1 = ASN1Parser(bitString.contentBytes());
    final keySeq = keyAsn1.nextObject() as ASN1Sequence;
    
    final modulus = (keySeq.elements[0] as ASN1Integer).valueAsBigInteger;
    final exponent = (keySeq.elements[1] as ASN1Integer).valueAsBigInteger;
    
    return RSAPublicKey(modulus, exponent);
  }
  
  Uint8List _privateKeyToBytes(RSAPrivateKey privateKey) {
    // Simplified private key serialization
    // In production, use proper ASN.1 serialization
    final bytes = <int>[];
    
    // Add modulus
    _addBigIntBytes(bytes, privateKey.modulus);
    
    // Add public exponent
    _addBigIntBytes(bytes, privateKey.publicExponent);
    
    // Add private exponent
    _addBigIntBytes(bytes, privateKey.privateExponent);
    
    // Add prime1
    _addBigIntBytes(bytes, privateKey.p);
    
    // Add prime2
    _addBigIntBytes(bytes, privateKey.q);
    
    // Add exponent1
    _addBigIntBytes(bytes, privateKey.dP);
    
    // Add exponent2
    _addBigIntBytes(bytes, privateKey.dQ);
    
    // Add coefficient
    _addBigIntBytes(bytes, privateKey.qInv);
    
    return Uint8List.fromList(bytes);
  }
  
  void _addBigIntBytes(List<int> bytes, BigInt value) {
    final hex = value.toRadixString(16);
    if (hex.length % 2 != 0) {
      bytes.add(0);
    }
    
    for (var i = 0; i < hex.length; i += 2) {
      final byte = int.parse(hex.substring(i, i + 2), radix: 16);
      bytes.add(byte);
    }
    
    // Add length delimiter
    bytes.add(0xFF);
  }
  
  String _splitPem(String base64Key) {
    final result = StringBuffer();
    for (var i = 0; i < base64Key.length; i += 64) {
      final end = i + 64;
      result.writeln(base64Key.substring(i, end < base64Key.length ? end : base64Key.length));
    }
    return result.toString().trim();
  }
  
  static Future<String> encrypt(String plaintext, String publicKeyPem) async {
    return await _instance.encryptWithPublicKey(plaintext, publicKeyPem);
  }
  
  static Future<String> decrypt(String encryptedBase64) async {
    return await _instance.decryptWithPrivateKey(encryptedBase64);
  }
  
  static Future<String> sign(String data) async {
    return await _instance.signData(data);
  }
  
  static Future<bool> verify(String data, String signature, String publicKeyPem) async {
    return await _instance.verifySignature(data, signature, publicKeyPem);
  }
  
  static bool get isInitialized => _isInitialized;
  
  Future<void> generateNewKeyPair({int keySize = 2048}) async {
    _keyPair = await _generateRSAKeyPair(keySize);
    _publicKey = _keyPair!.publicKey;
    _privateKey = _keyPair!.privateKey;
    
    SecurityManager()._logSecurityEvent(
      SecurityEvent(
        type: SecurityEventType.initialized,
        severity: SecuritySeverity.info,
        message: 'RSA key pair regenerated',
        timestamp: DateTime.now(),
      ),
    );
  }
  
  Future<void> clearKeys() async {
    _keyPair = null;
    _publicKey = null;
    _privateKey = null;
    _isInitialized = false;
  }
}
