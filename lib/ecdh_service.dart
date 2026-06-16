import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:pointycastle/export.dart' as pc;

class LocalSecretKey {
  final Uint8List bytes;
  LocalSecretKey(this.bytes);
}

abstract class IEcdhService {
  Future<void> init();
  Future<List<int>> getPublicKeyBytes();
  Future<LocalSecretKey> computeSharedAesKey(List<int> serverPublicKeyBytes);
  Future<Map<String, dynamic>> encrypt(String plainText, LocalSecretKey key);
  Future<String> decrypt(Map<String, dynamic> data, LocalSecretKey key);
  Future<void> saveSessionLocally(LocalSecretKey aesKey, String sessionId);
  Future<LocalSecretKey?> getStoredAesKey();
  Future<String?> getStoredSessionId();
  Future<void> clearStoredSession();
  void dispose();
}

class EcdhService implements IEcdhService {

  pc.ECPrivateKey? _privateKey;
  pc.ECPublicKey? _publicKey;

  final FlutterSecureStorage _secureStorage = const FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
  );

  static const String _storageAesKeyName = 'secure_session_aes_key';
  static const String _storageSessionIdName = 'secure_session_id';

  @override
  Future<void> init() async {
    final domainParams = pc.ECDomainParameters('secp256r1');
    final keyGen = pc.ECKeyGenerator();

    final random = pc.SecureRandom('Fortuna')
      ..seed(pc.KeyParameter(Uint8List.fromList(
        List.generate(32, (i) => DateTime.now().microsecondsSinceEpoch % 256)
      )));

    keyGen.init(pc.ParametersWithRandom(
      pc.ECKeyGeneratorParameters(domainParams),
      random,
    ));

    final pair = keyGen.generateKeyPair();
    _privateKey = pair.privateKey as pc.ECPrivateKey;
    _publicKey = pair.publicKey as pc.ECPublicKey;
  }

  List<int> _padTo32Bytes(List<int> bytes) {
    if (bytes.length == 32) return bytes;
    if (bytes.length > 32) return bytes.sublist(bytes.length - 32);
    return [...List.filled(32 - bytes.length, 0), ...bytes];
  }

  List<int> _hexDecode(String hex) {
    final bytes = <int>[];
    for (var i = 0; i < hex.length; i += 2) {
      bytes.add(int.parse(hex.substring(i, i + 2), radix: 16));
    }
    return bytes;
  }

  @override
  Future<List<int>> getPublicKeyBytes() async {
    if (_publicKey == null) throw StateError("Service non initialise. Appelez init().");

    // getEncoded(false) retourne le point non compresse : [0x04, x, y] = 65 bytes
    final encoded = _publicKey!.Q!.getEncoded(false);
    return encoded.toList();
  }

  @override
  Future<LocalSecretKey> computeSharedAesKey(List<int> serverPublicKeyBytes) async {
    if (_privateKey == null) throw StateError("Service non initialise. Appelez init().");

    print('Longueur totale du paquet serveur recu : ${serverPublicKeyBytes.length}');

    // Retirer le header X.509 de 26 octets du serveur Java
    final rawServerBytes = serverPublicKeyBytes.sublist(26);

    // Reconstruction du point EC serveur depuis les bytes bruts
    final domainParams = pc.ECDomainParameters('secp256r1');
    final serverPoint = domainParams.curve.decodePoint(rawServerBytes);
    final serverPublicKey = pc.ECPublicKey(serverPoint, domainParams);

    // Accord ECDH
    final agreement = pc.ECDHBasicAgreement()..init(_privateKey!);
    final sharedSecretBigInt = agreement.calculateAgreement(serverPublicKey);

    // Conversion BigInt en bytes de 32 octets
    String hexString = sharedSecretBigInt.toRadixString(16);
    if (hexString.length % 2 != 0) hexString = '0$hexString';
    final sharedSecretBytes = _padTo32Bytes(_hexDecode(hexString));

    print('Secret partage Flutter (premiers 8 bytes) : ${sharedSecretBytes.sublist(0, 8)}');

    // Derivation HKDF-SHA256 
    final hkdfParams = pc.HkdfParameters(
      Uint8List.fromList(sharedSecretBytes),
      32,
      null,
      Uint8List.fromList(utf8.encode('ecdh-aes-key')),
    );
    final hkdf = pc.KeyDerivator('SHA-256/HKDF')..init(hkdfParams);
    final aesBytes = Uint8List(32);
    hkdf.deriveKey(Uint8List(0), 0, aesBytes, 0);

    print('Cle AES Flutter (premiers 8 bytes) : ${aesBytes.sublist(0, 8)}');

    return LocalSecretKey(aesBytes);
  }

  @override
  Future<Map<String, dynamic>> encrypt(String plainText, LocalSecretKey key) async {
    // Generation IV aleatoire de 12 bytes
    final random = pc.SecureRandom('Fortuna')
      ..seed(pc.KeyParameter(Uint8List.fromList(
        List.generate(32, (i) => DateTime.now().microsecondsSinceEpoch % 256)
      )));
    final iv = random.nextBytes(12);

    // Chiffrement AES-256-GCM
    final cipher = pc.GCMBlockCipher(pc.AESEngine());
    cipher.init(true, pc.AEADParameters(
      pc.KeyParameter(key.bytes), 128, iv, Uint8List(0)
    ));

    final inputBytes = Uint8List.fromList(utf8.encode(plainText));
    final cipherTextWithTag = cipher.process(inputBytes);

    // Separation cipherText et tag (16 derniers bytes = tag GCM)
    final cipherTextLen = cipherTextWithTag.length - 16;
    final cipherText = cipherTextWithTag.sublist(0, cipherTextLen);
    final tag = cipherTextWithTag.sublist(cipherTextLen);

    return {
      'cipherText': base64Encode(cipherText),
      'iv':         base64Encode(iv),
      'tag':        base64Encode(tag),
    };
  }

  @override
  Future<String> decrypt(Map<String, dynamic> data, LocalSecretKey key) async {
    final cipherText = base64Decode(data['cipherText'] as String);
    final iv         = base64Decode(data['iv'] as String);
    final tag        = base64Decode(data['tag'] as String);

    // Reconstitution bloc combine [cipherText + tag] attendu par PointyCastle
    final cipherTextWithTag = Uint8List(cipherText.length + tag.length);
    cipherTextWithTag.setAll(0, cipherText);
    cipherTextWithTag.setAll(cipherText.length, tag);

    final cipher = pc.GCMBlockCipher(pc.AESEngine());
    cipher.init(false, pc.AEADParameters(
      pc.KeyParameter(key.bytes), 128, iv, Uint8List(0)
    ));

    final plainBytes = cipher.process(cipherTextWithTag);
    return utf8.decode(plainBytes);
  }

  @override
  Future<void> saveSessionLocally(LocalSecretKey aesKey, String sessionId) async {
    if (aesKey.bytes.isEmpty) throw StateError('Impossible de sauvegarder une cle vide');
    await _secureStorage.write(key: _storageAesKeyName, value: base64Encode(aesKey.bytes));
    await _secureStorage.write(key: _storageSessionIdName, value: sessionId);
  }

  @override
  Future<LocalSecretKey?> getStoredAesKey() async {
    final base64Key = await _secureStorage.read(key: _storageAesKeyName);
    if (base64Key == null) return null;
    return LocalSecretKey(base64Decode(base64Key));
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

  @override
  void dispose() {
    _privateKey = null;
    _publicKey = null;
  }
}