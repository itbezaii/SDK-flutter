import 'dart:convert';
import 'package:cryptography/cryptography.dart';
import 'package:cryptography_flutter/cryptography_flutter.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// Interface du service ECDH décrivant le contrat du SDK Mobile
abstract class IEcdhService {
  Future<void> init();
  Future<List<int>> getPublicKeyBytes();
  Future<SecretKey> computeSharedAesKey(List<int> serverPublicKeyBytes);
  Future<Map<String, dynamic>> encrypt(String plainText, SecretKey key);
  Future<String> decrypt(Map<String, dynamic> data, SecretKey key);
  Future<void> saveSessionLocally(SecretKey aesKey, String sessionId);
  Future<SecretKey?> getStoredAesKey();
  Future<String?> getStoredSessionId();
  Future<void> clearStoredSession();
  void dispose();
}

/// Implémentation ECDH P-256 + HKDF + AES-256-GCM + Stockage Sécurisé Matériel
class EcdhService implements IEcdhService {

  final Ecdh _ecdh = Ecdh.p256(length: 32);
  final Hkdf _hkdf = Hkdf(
    hmac: Hmac.sha256(),
    outputLength: 32,
  );
  final AesGcm _aesGcm = AesGcm.with256bits();

  final FlutterSecureStorage _secureStorage = const FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
  );

  static const String _storageAesKeyName = 'secure_session_aes_key';
  static const String _storageSessionIdName = 'secure_session_id';

  // En-tête ASN.1 X.509 constant pour la courbe secp256r1 (OID 1.2.840.10045.3.1.7)
  // Toujours identique pour P-256 → 26 octets fixes
  static const List<int> _x509Header = [
    48, 89, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1,
    6, 8, 42, 134, 72, 206, 61, 3, 1, 7, 3, 66, 0
  ];

  SimpleKeyPair? _keyPair;

  @override
  Future<void> init() async {
    FlutterCryptography.enable();
    _keyPair = await _ecdh.newKeyPair();
  }

  /// Retourne la clé publique Flutter encapsulée au format X.509
  /// pour être décodée par Java via X509EncodedKeySpec (91 octets au total)
  @override
  Future<List<int>> getPublicKeyBytes() async {
    if (_keyPair == null) throw StateError("Service non initialisé. Appelez init().");
    final publicKey = await _keyPair!.extractPublicKey();

    // Bytes bruts du point P-256 (65 octets, commence par 0x04)
    final rawBytes = publicKey.bytes;

    // Injection de l'en-tête X.509 devant les bytes bruts
    return [..._x509Header, ...rawBytes];
  }

  /// Calcul de la clé AES partagée à partir de la clé publique X.509 reçue de Spring Boot
  @override
  Future<SecretKey> computeSharedAesKey(List<int> serverPublicKeyBytes) async {
    if (_keyPair == null) throw StateError("Service non initialisé. Appelez init().");

    // Java envoie sa clé en X.509 → on retire les 26 octets d'en-tête
    // pour ne garder que les bytes bruts que le package cryptography attend
    final rawServerBytes = serverPublicKeyBytes.sublist(26);

    final serverPublicKey = SimplePublicKey(
      rawServerBytes,
      type: KeyPairType.p256,
    );

    final sharedSecret = await _ecdh.sharedSecretKey(
      keyPair: _keyPair!,
      remotePublicKey: serverPublicKey,
    );

    // HKDF_INFO identique au côté Java : "ecdh-aes-key"
    return await _hkdf.deriveKey(
      secretKey: sharedSecret,
      nonce: utf8.encode('ecdh-aes-key'),
    );
  }

  /// Chiffrement AES-256-GCM — format JSON aligné avec EcdhService.java
  @override
  Future<Map<String, dynamic>> encrypt(String plainText, SecretKey key) async {
    final secretBox = await _aesGcm.encrypt(
      utf8.encode(plainText),
      secretKey: key,
    );

    return {
      'cipherText': base64Encode(secretBox.cipherText),
      'iv':         base64Encode(secretBox.nonce),
      'tag':        base64Encode(secretBox.mac.bytes),
    };
  }

  /// Déchiffrement AES-256-GCM d'une payload JSON reçue du serveur
  @override
  Future<String> decrypt(Map<String, dynamic> data, SecretKey key) async {
    final secretBox = SecretBox(
      base64Decode(data['cipherText'] as String),
      nonce: base64Decode(data['iv'] as String),
      mac:   Mac(base64Decode(data['tag'] as String)),
    );

    final clearBytes = await _aesGcm.decrypt(secretBox, secretKey: key);
    return utf8.decode(clearBytes);
  }

  /// Sauvegarde chiffrée de la session dans le Keystore / Keychain matériel
  @override
  Future<void> saveSessionLocally(SecretKey aesKey, String sessionId) async {
    final keyBytes  = await aesKey.extractBytes();
    final base64Key = base64Encode(keyBytes);

    await _secureStorage.write(key: _storageAesKeyName,    value: base64Key);
    await _secureStorage.write(key: _storageSessionIdName, value: sessionId);
  }

  @override
  Future<SecretKey?> getStoredAesKey() async {
    final base64Key = await _secureStorage.read(key: _storageAesKeyName);
    if (base64Key == null) return null;
    return SecretKey(base64Decode(base64Key));
  }

  @override
  Future<String?> getStoredSessionId() async {
    return await _secureStorage.read(key: _storageSessionIdName);
  }

  @override
  Future<void> clearStoredSession() async {
    await _secureStorage.delete(key: _storageAesKeyName);
    await _secureStorage.delete(key: _storageSessionIdName);
  }

  /// Destruction de la clé éphémère après handshake
  @override
  void dispose() {
    _keyPair?.destroy();
    _keyPair = null;
  }
}