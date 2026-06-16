import 'dart:convert';
import 'dart:typed_data';
import 'package:http/http.dart' as http;
import 'package:firebase_app_check/firebase_app_check.dart';
import 'ecdh_service.dart';

class SecureHttpClient extends http.BaseClient {
  final http.Client _inner = http.Client();
  final IEcdhService _ecdhService;
  final String _backendUrl;
  String? _appCheckToken;

  SecureHttpClient({
    required IEcdhService ecdhService,
    required String backendUrl,
    String? appCheckToken,
  })  : _ecdhService = ecdhService,
        _backendUrl = backendUrl,
        _appCheckToken = appCheckToken;

  void updateAppCheckToken(String token) {
    _appCheckToken = token;
  }

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    final freshToken = await FirebaseAppCheck.instance.getToken();
    if (freshToken != null) _appCheckToken = freshToken;

    if (_appCheckToken != null) {
      request.headers['X-Firebase-AppCheck'] = _appCheckToken!;
    }
    final sessionId = await _ecdhService.getStoredSessionId();
    if (sessionId != null) {
      request.headers['X-Session-Id'] = sessionId;
    }

    final response = await _inner.send(request);

    if (response.statusCode == 401) {
      print('Session expiree. Silent Re-handshake en cours...');
      final success = await _doHandshake();
      if (!success) return response;

      final newSessionId = await _ecdhService.getStoredSessionId();
      final retryRequest = _cloneRequest(request, newSessionId);
      print('Re-handshake reussi. Rejeu de la requete...');
      return await _inner.send(retryRequest);
    }

    return response;
  }

  // Methode principale pour envoyer des donnees chiffrees
  // Prend le plaintext, chiffre, envoie, gere le re-handshake si besoin
  Future<String> sendEncrypted(String endpoint, String plainText) async {
    final freshToken = await FirebaseAppCheck.instance.getToken();
    if (freshToken != null) _appCheckToken = freshToken;

    // Premiere tentative
    String? result = await _trySendEncrypted(endpoint, plainText);

    if (result == null) {
      // 401 recu — faire le re-handshake et reessayer
      print('Session expiree. Silent Re-handshake en cours...');
      final success = await _doHandshake();
      if (!success) throw Exception('Re-handshake echoue');

      // Deuxieme tentative avec la nouvelle cle
      result = await _trySendEncrypted(endpoint, plainText);
      if (result == null) throw Exception('Echec apres re-handshake');

      print('Re-handshake reussi. Requete rejouee avec succes.');
    }

    return result;
  }

  // Retourne le plaintext dechiffre si succes, null si 401
  Future<String?> _trySendEncrypted(String endpoint, String plainText) async {
    // 1. Lire la cle AES et le sessionId actuels
    final aesKey = await _ecdhService.getStoredAesKey();
    final sessionId = await _ecdhService.getStoredSessionId();

    if (aesKey == null || sessionId == null) {
      throw Exception('Aucune session active. Effectuez le handshake.');
    }

    // 2. Chiffrer le plaintext avec la cle actuelle
    final encryptedPayload = await _ecdhService.encrypt(plainText, aesKey);

    // 3. Envoyer la requete
    final response = await _inner.post(
      Uri.parse('$_backendUrl$endpoint'),
      headers: {
        'Content-Type': 'application/json',
        'X-Firebase-AppCheck': _appCheckToken ?? '',
        'X-Session-Id': sessionId,
      },
      body: jsonEncode(encryptedPayload),
    );

    // 4. Session expiree → retourner null pour declencher re-handshake
    if (response.statusCode == 401) return null;

    if (response.statusCode != 200) {
      throw Exception('Erreur serveur : ${response.statusCode}');
    }

    // 5. Dechiffrer la reponse avec la meme cle
    final encryptedResponse = jsonDecode(response.body) as Map<String, dynamic>;
    return await _ecdhService.decrypt(encryptedResponse, aesKey);
  }

  Future<bool> _doHandshake() async {
    try {
      await _ecdhService.init();
      final clientPublicKeyBytes = await _ecdhService.getPublicKeyBytes();

      final handshakeResponse = await _inner.post(
        Uri.parse('$_backendUrl/api/security/handshake'),
        headers: {
          'Content-Type': 'application/json',
          'X-Firebase-AppCheck': _appCheckToken ?? '',
        },
        body: jsonEncode({
          'clientPublicKey': base64Encode(clientPublicKeyBytes),
        }),
      );

      if (handshakeResponse.statusCode == 200) {
        final data = jsonDecode(handshakeResponse.body);
        final serverPublicKeyBytes = base64Decode(data['serverPublicKey'] as String);
        final newSessionId = data['sessionId'] as String;

        final newAesKey = await _ecdhService.computeSharedAesKey(serverPublicKeyBytes);
        await _ecdhService.saveSessionLocally(newAesKey, newSessionId);
        _ecdhService.dispose();
        return true;
      }
      return false;
    } catch (e) {
      print('Erreur durant le Silent Re-handshake : $e');
      return false;
    }
  }

  http.BaseRequest _cloneRequest(http.BaseRequest original, String? newSessionId) {
    final cloned = http.Request(original.method, original.url);
    cloned.headers.addAll(original.headers);
    if (newSessionId != null) {
      cloned.headers['X-Session-Id'] = newSessionId;
    }
    if (original is http.Request) {
      cloned.body = original.body;
    }
    return cloned;
  }
}