import 'dart:convert';
import 'dart:typed_data';
import 'package:encrypt/encrypt.dart';
import 'package:crypto/crypto.dart';
import 'package:pointycastle/export.dart';
import '../security_manager.dart';

class AESEncryption {
  static final AESEncryption _instance = AESEncryption._internal();
  factory AESEncryption() => _instance;
  AESEncryption._internal();
  
  static bool _isInitialized = false;
  static Key? _encryptionKey;
  static IV? _encryptionIV;
  
  Future<void> initialize({String? customKey}) async {
    if (_isInitialized) {
      throw SecurityException('AESEncryption already initialized');
    }
    
    try {
      // Generate or use provided key
      if (customKey != null) {
        _encryptionKey = _generateKeyFromString(customKey);
      } else {
        _encryptionKey = await _generateSecureKey();
      }
      
      // Generate IV (Initialization Vector)
      _encryptionIV = _generateIV();
      
      _isInitialized = true;
      
      SecurityManager()._logSecurityEvent(
        SecurityEvent(
          type: SecurityEventType.initialized,
          severity: SecuritySeverity.info,
          message: 'AESEncryption initialized',
          timestamp: DateTime.now(),
        ),
      );
    } catch (e) {
      SecurityManager()._logSecurityEvent(
        SecurityEvent(
          type: SecurityEventType.encryptionError,
          severity: SecuritySeverity.critical,
          message: 'Failed to initialize AESEncryption: $e',
          timestamp: DateTime.now(),
        ),
      );
      rethrow;
    }
  }
  
  Future<String> encrypt(String plaintext, {String? key}) async {
    if (!_isInitialized) {
      await initialize();
    }
    
    try {
      final encryptKey = key != null ? _generateKeyFromString(key) : _encryptionKey!;
      final iv = _encryptionIV!;
      
      final encrypter = Encrypter(AES(encryptKey, mode: AESMode.cbc));
      final encrypted = encrypter.encrypt(plaintext, iv: iv);
      
      // Combine IV and ciphertext for storage
      final combined = '${iv.base64}:${encrypted.base64}';
      
      return combined;
    } catch (e) {
      SecurityManager()._logSecurityEvent(
        SecurityEvent(
          type: SecurityEventType.encryptionError,
          severity: SecuritySeverity.high,
          message: 'Encryption failed: $e',
          timestamp: DateTime.now(),
          metadata: {'operation': 'encrypt'},
        ),
      );
      throw SecurityException('Encryption failed: ${e.toString()}');
    }
  }
  
  Future<String> decrypt(String encryptedText, {String? key}) async {
    if (!_isInitialized) {
      await initialize();
    }
    
    try {
      // Split IV and ciphertext
      final parts = encryptedText.split(':');
      if (parts.length != 2) {
        throw SecurityException('Invalid encrypted text format');
      }
      
      final iv = IV(base64.decode(parts[0]));
      final ciphertext = Encrypted(base64.decode(parts[1]));
      
      final decryptKey = key != null ? _generateKeyFromString(key) : _encryptionKey!;
      final decrypter = Encrypter(AES(decryptKey, mode: AESMode.cbc));
      
      final decrypted = decrypter.decrypt(ciphertext, iv: iv);
      
      return decrypted;
    } catch (e) {
      SecurityManager()._logSecurityEvent(
        SecurityEvent(
          type: SecurityEventType.decryptionError,
          severity: SecuritySeverity.high,
          message: 'Decryption failed: $e',
          timestamp: DateTime.now(),
          metadata: {'operation': 'decrypt'},
        ),
      );
      throw SecurityException('Decryption failed: ${e.toString()}');
    }
  }
  
  Future<Uint8List> encryptBytes(Uint8List data, {String? key}) async {
    if (!_isInitialized) {
      await initialize();
    }
    
    try {
      final encryptKey = key != null ? _generateKeyFromString(key) : _encryptionKey!;
      final iv = _encryptionIV!;
      
      final encrypter = Encrypter(AES(encryptKey, mode: AESMode.cbc));
      final encrypted = encrypter.encryptBytes(data, iv: iv);
      
      // Combine IV and ciphertext
      final combined = Uint8List(iv.bytes.length + encrypted.bytes.length);
      combined.setAll(0, iv.bytes);
      combined.setAll(iv.bytes.length, encrypted.bytes);
      
      return combined;
    } catch (e) {
      SecurityManager()._logSecurityEvent(
        SecurityEvent(
          type: SecurityEventType.encryptionError,
          severity: SecuritySeverity.high,
          message: 'Bytes encryption failed: $e',
          timestamp: DateTime.now(),
        ),
      );
      throw SecurityException('Bytes encryption failed');
    }
  }
  
  Future<Uint8List> decryptBytes(Uint8List encryptedData, {String? key}) async {
    if (!_isInitialized) {
      await initialize();
    }
    
    try {
      // Extract IV (first 16 bytes) and ciphertext
      if (encryptedData.length <= 16) {
        throw SecurityException('Invalid encrypted data');
      }
      
      final ivBytes = encryptedData.sublist(0, 16);
      final cipherBytes = encryptedData.sublist(16);
      
      final iv = IV(ivBytes);
      final ciphertext = Encrypted(cipherBytes);
      
      final decryptKey = key != null ? _generateKeyFromString(key) : _encryptionKey!;
      final decrypter = Encrypter(AES(decryptKey, mode: AESMode.cbc));
      
      final decrypted = decrypter.decryptBytes(ciphertext, iv: iv);
      
      return Uint8List.fromList(decrypted);
    } catch (e) {
      SecurityManager()._logSecurityEvent(
        SecurityEvent(
          type: SecurityEventType.decryptionError,
          severity: SecuritySeverity.high,
          message: 'Bytes decryption failed: $e',
          timestamp: DateTime.now(),
        ),
      );
      throw SecurityException('Bytes decryption failed');
    }
  }
  
  Future<String> encryptWithPassword(
    String plaintext,
    String password, {
    int iterations = 10000,
  }) async {
    try {
      // Generate key from password using PBKDF2
      final salt = _generateSalt();
      final key = await _deriveKeyFromPassword(password, salt, iterations);
      
      // Generate IV
      final iv = _generateIV();
      
      // Encrypt
      final encrypter = Encrypter(AES(Key(key), mode: AESMode.cbc));
      final encrypted = encrypter.encrypt(plaintext, iv: iv);
      
      // Combine salt, IV, iterations and ciphertext
      final combined = '${base64.encode(salt)}:${iv.base64}:$iterations:${encrypted.base64}';
      
      return combined;
    } catch (e) {
      SecurityManager()._logSecurityEvent(
        SecurityEvent(
          type: SecurityEventType.encryptionError,
          severity: SecuritySeverity.high,
          message: 'Password-based encryption failed: $e',
          timestamp: DateTime.now(),
        ),
      );
      throw SecurityException('Password-based encryption failed');
    }
  }
  
  Future<String> decryptWithPassword(
    String encryptedText,
    String password,
  ) async {
    try {
      // Split components
      final parts = encryptedText.split(':');
      if (parts.length != 4) {
        throw SecurityException('Invalid encrypted text format');
      }
      
      final salt = base64.decode(parts[0]);
      final iv = IV(base64.decode(parts[1]));
      final iterations = int.parse(parts[2]);
      final ciphertext = Encrypted(base64.decode(parts[3]));
      
      // Derive key from password
      final key = await _deriveKeyFromPassword(password, salt, iterations);
      
      // Decrypt
      final decrypter = Encrypter(AES(Key(key), mode: AESMode.cbc));
      final decrypted = decrypter.decrypt(ciphertext, iv: iv);
      
      return decrypted;
    } catch (e) {
      SecurityManager()._logSecurityEvent(
        SecurityEvent(
          type: SecurityEventType.decryptionError,
          severity: SecuritySeverity.high,
          message: 'Password-based decryption failed: $e',
          timestamp: DateTime.now(),
        ),
      );
      throw SecurityException('Password-based decryption failed');
    }
  }
  
  Key _generateKeyFromString(String keyString) {
    // Ensure key is exactly 32 bytes for AES-256
    var keyBytes = utf8.encode(keyString);
    
    if (keyBytes.length < 32) {
      // Pad with zeros if too short
      keyBytes = List<int>.from(keyBytes)
        ..addAll(List.filled(32 - keyBytes.length, 0));
    } else if (keyBytes.length > 32) {
      // Truncate if too long
      keyBytes = keyBytes.sublist(0, 32);
    }
    
    return Key(Uint8List.fromList(keyBytes));
  }
  
  Future<Key> _generateSecureKey() async {
    // Generate cryptographically secure random key
    final secureRandom = FortunaRandom();
    final seedSource = Random.secure();
    final seeds = <int>[];
    
    for (var i = 0; i < 32; i++) {
      seeds.add(seedSource.nextInt(256));
    }
    
    secureRandom.seed(KeyParameter(Uint8List.fromList(seeds)));
    
    final keyBytes = Uint8List(32);
    for (var i = 0; i < keyBytes.length; i++) {
      keyBytes[i] = secureRandom.nextUint8();
    }
    
    return Key(keyBytes);
  }
  
  IV _generateIV() {
    // Generate random IV (16 bytes for AES)
    final secureRandom = Random.secure();
    final ivBytes = List<int>.generate(16, (_) => secureRandom.nextInt(256));
    
    return IV(Uint8List.fromList(ivBytes));
  }
  
  Uint8List _generateSalt() {
    // Generate random salt (16 bytes)
    final secureRandom = Random.secure();
    return Uint8List.fromList(
      List<int>.generate(16, (_) => secureRandom.nextInt(256)),
    );
  }
  
  Future<Uint8List> _deriveKeyFromPassword(
    String password,
    Uint8List salt,
    int iterations,
  ) async {
    // PBKDF2 key derivation
    final pbkdf2 = PBKDF2KeyDerivator(HMac(SHA256Digest(), 64));
    pbkdf2.init(Pbkdf2Parameters(salt, iterations, 32));
    
    final key = pbkdf2.process(utf8.encode(password));
    return Uint8List.fromList(key);
  }
  
  // Static convenience methods
  static Future<String> encryptString(String plaintext, {String? key}) async {
    return await _instance.encrypt(plaintext, key: key);
  }
  
  static Future<String> decryptString(String encryptedText, {String? key}) async {
    return await _instance.decrypt(encryptedText, key: key);
  }
  
  static Future<Uint8List> encryptData(Uint8List data, {String? key}) async {
    return await _instance.encryptBytes(data, key: key);
  }
  
  static Future<Uint8List> decryptData(Uint8List encryptedData, {String? key}) async {
    return await _instance.decryptBytes(encryptedData, key: key);
  }
  
  static bool get isInitialized => _isInitialized;
  
  Future<void> rotateKey() async {
    // Generate new encryption key
    _encryptionKey = await _generateSecureKey();
    _encryptionIV = _generateIV();
    
    SecurityManager()._logSecurityEvent(
      SecurityEvent(
        type: SecurityEventType.initialized,
        severity: SecuritySeverity.info,
        message: 'Encryption keys rotated',
        timestamp: DateTime.now(),
      ),
    );
  }
  
  Future<void> clearKeys() async {
    _encryptionKey = null;
    _encryptionIV = null;
    _isInitialized = false;
  }
}
   
