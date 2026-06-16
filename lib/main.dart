import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:firebase_core/firebase_core.dart';
import 'package:firebase_app_check/firebase_app_check.dart';
import 'package:safe_device/safe_device.dart';
import 'firebase_options.dart';
import 'ecdh_service.dart';
import 'secure_http_client.dart';

// URL de base du backend Spring Boot
// 10.0.2.2 est l'adresse de la machine hôte vue depuis l'émulateur Android
const String kBackendUrl = 'http://192.168.1.105:8080';

void main() async {
  // Garantit que les bindings Flutter sont initialisés avant tout appel async
  WidgetsFlutterBinding.ensureInitialized();

  // Initialisation de Firebase avec les options générées par flutterfire configure
  await Firebase.initializeApp(
    options: DefaultFirebaseOptions.currentPlatform,
  );

  // Activation d'AppCheck en mode debug pour l'émulateur
  // En production, remplacer par AndroidProvider.playIntegrity
  await FirebaseAppCheck.instance.activate(
    androidProvider: AndroidProvider.debug,
  );

  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Security SDK Demo',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.indigo),
        useMaterial3: true,
      ),
      home: const HomeScreen(),
    );
  }
}

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {

  // Service cryptographique — une seule instance pour toute la session
  final IEcdhService _ecdhService = EcdhService();

  // Client HTTP sécurisé avec interception 401 et re-handshake silencieux
  late final SecureHttpClient _secureClient;

  // Controleur du champ de saisie du message a chiffrer
  final TextEditingController _messageController = TextEditingController();

  // Token AppCheck courant
  String? _appCheckToken;

  // Variables d'affichage de l'interface
  String _deviceStatus      = 'Non verifie';
  String _appCheckStatus    = 'Non obtenu';
  String _handshakeStatus   = 'Non effectue';
  String _encryptionStatus  = 'En attente';
  String _sessionStatus     = 'Non verifie';
  String _serverResponse    = '';

  @override
  void initState() {
    super.initState();
    // Initialisation du client HTTP avec les references au service et au backend
    _secureClient = SecureHttpClient(
      ecdhService: _ecdhService,
      backendUrl: kBackendUrl,
    );
  }

  @override
  void dispose() {
    _messageController.dispose();
    super.dispose();
  }

  // ----------------------------------------------------------------
  // SECTION 1 : Detection root / jailbreak
  // ----------------------------------------------------------------
  Future<void> _checkDevice() async {
    setState(() => _deviceStatus = 'Verification en cours...');
    try {
      final bool isRooted = await SafeDevice.isJailBroken;
      setState(() {
        _deviceStatus = isRooted
            ? 'ALERTE : Appareil compromis (roote ou jailbreake)'
            : 'Appareil sain - Aucune compromission detectee';
      });
    } catch (e) {
      setState(() => _deviceStatus = 'Erreur : $e');
    }
  }

  // ----------------------------------------------------------------
  // SECTION 2 : Obtention du token Firebase AppCheck
  // ----------------------------------------------------------------
  Future<void> _getAppCheckToken() async {
    setState(() => _appCheckStatus = 'Obtention du token...');
    try {
      final String? token = await FirebaseAppCheck.instance.getToken();
      if (token == null) {
        setState(() => _appCheckStatus = 'Echec : token null');
        return;
      }
      _appCheckToken = token;

      // Injecter le token dans le client HTTP pour toutes les requetes suivantes
      _secureClient.updateAppCheckToken(token);

      // Afficher seulement les 30 premiers caracteres pour la lisibilite
      setState(() {
        _appCheckStatus = 'Token obtenu : ${token.substring(0, 30)}...';
        print('Token AppCheck obtenu : $token');
      });
    } catch (e) {
      setState(() => _appCheckStatus = 'Erreur : $e');
    }
  }


  // SECTION 3 : Handshake ECDH

 Future<void> _doHandshake() async {
  if (_appCheckToken == null) {
    setState(() => _handshakeStatus = 'Obtenez d abord le token AppCheck');
    return;
  }

  setState(() => _handshakeStatus = 'Handshake en cours...');
  try {
    await _ecdhService.init();

    final List<int> clientPublicKeyBytes = await _ecdhService.getPublicKeyBytes();

    final response = await _secureClient.post(
      Uri.parse('$kBackendUrl/api/security/handshake'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'clientPublicKey': base64Encode(clientPublicKeyBytes),
      }),
    );

    if (response.statusCode != 200) {
      setState(() => _handshakeStatus = 'Echec serveur : ${response.statusCode}');
      return;
    }

    final Map<String, dynamic> data = jsonDecode(response.body);
    final List<int> serverPublicKeyBytes = base64Decode(data['serverPublicKey']);
    final String sessionId = data['sessionId'];

    // Calcul de la cle AES partagee
    final sharedAesKey = await _ecdhService.computeSharedAesKey(serverPublicKeyBytes);

    // Sauvegarde unique avec les bonnes variables
    await _ecdhService.saveSessionLocally(sharedAesKey, sessionId);

    // Destruction de la paire de cles ephemere
    _ecdhService.dispose();

    setState(() {
      _handshakeStatus = 'Succes - SessionId : ${sessionId.substring(0, 8)}...';
    });

  } catch (e) {
    setState(() => _handshakeStatus = 'Erreur : $e');
  }
}

  // SECTION 4 : Envoi d'une donnee chiffree

 Future<void> _sendSecureData() async {
  final String message = _messageController.text.trim();
  if (message.isEmpty) {
    setState(() => _encryptionStatus = 'Saisissez un message a chiffrer');
    return;
  }

  setState(() {
    _encryptionStatus = 'Chiffrement et envoi en cours...';
    _serverResponse = '';
  });

  try {
    // Le client gere tout : chiffrement, envoi, re-handshake si besoin, dechiffrement
    final decryptedResponse = await _secureClient.sendEncrypted(
      '/api/security/secure-data',
      message,
    );

    setState(() {
      _encryptionStatus = 'Reponse recue et dechiffree avec succes';
      _serverResponse = decryptedResponse;
    });

  } catch (e) {
    setState(() => _encryptionStatus = 'Erreur : $e');
  }
}

  // SECTION 5 : Verification et effacement de la session locale

  Future<void> _checkStoredSession() async {
    setState(() => _sessionStatus = 'Lecture du secure storage...');
    try {
      final String? sessionId = await _ecdhService.getStoredSessionId();
      final storedKey = await _ecdhService.getStoredAesKey();

      setState(() {
        if (sessionId != null && storedKey != null) {
          _sessionStatus =
              'Session active - SessionId : ${sessionId.substring(0, 8)}... - Cle AES presente';
        } else {
          _sessionStatus = 'Aucune session stockee';
        }
      });
    } catch (e) {
      setState(() => _sessionStatus = 'Erreur : $e');
    }
  }

  Future<void> _clearSession() async {
    await _ecdhService.clearStoredSession();
    setState(() {
      _sessionStatus = 'Session effacee du secure storage';
      _handshakeStatus = 'Non effectue';
      _encryptionStatus = 'En attente';
      _serverResponse = '';
    });
  }

  // ----------------------------------------------------------------
  // INTERFACE GRAPHIQUE
  // ----------------------------------------------------------------
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Security SDK Demo'),
        backgroundColor: Theme.of(context).colorScheme.inversePrimary,
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [

            // --- Section 1 : Appareil ---
            _buildSectionTitle('1. Securite de l appareil'),
            _buildStatusCard(_deviceStatus),
            ElevatedButton(
              onPressed: _checkDevice,
              child: const Text('Verifier l appareil'),
            ),

            const SizedBox(height: 24),

            // --- Section 2 : AppCheck ---
            _buildSectionTitle('2. Firebase AppCheck'),
            _buildStatusCard(_appCheckStatus),
            ElevatedButton(
              onPressed: _getAppCheckToken,
              child: const Text('Obtenir token AppCheck'),
            ),

            const SizedBox(height: 24),

            // --- Section 3 : Handshake ---
            _buildSectionTitle('3. Handshake ECDH'),
            _buildStatusCard(_handshakeStatus),
            ElevatedButton(
              onPressed: _doHandshake,
              child: const Text('Lancer le handshake'),
            ),

            const SizedBox(height: 24),

            // --- Section 4 : Chiffrement ---
            _buildSectionTitle('4. Chiffrement AES-256-GCM'),
            TextField(
              controller: _messageController,
              decoration: const InputDecoration(
                labelText: 'Message a chiffrer',
                border: OutlineInputBorder(),
              ),
            ),
            const SizedBox(height: 8),
            _buildStatusCard(_encryptionStatus),
            if (_serverResponse.isNotEmpty)
              _buildStatusCard('Reponse serveur : $_serverResponse'),
            ElevatedButton(
              onPressed: _sendSecureData,
              child: const Text('Envoyer chiffre'),
            ),

            const SizedBox(height: 24),

            // --- Section 5 : Session ---
            _buildSectionTitle('5. Session locale'),
            _buildStatusCard(_sessionStatus),
            Row(
              children: [
                Expanded(
                  child: ElevatedButton(
                    onPressed: _checkStoredSession,
                    child: const Text('Verifier session'),
                  ),
                ),
                const SizedBox(width: 8),
                Expanded(
                  child: ElevatedButton(
                    onPressed: _clearSession,
                    style: ElevatedButton.styleFrom(
                      backgroundColor: Colors.red.shade100,
                    ),
                    child: const Text('Effacer session'),
                  ),
                ),
              ],
            ),

          ],
        ),
      ),
    );
  }

  // Widget utilitaire : titre de section
  Widget _buildSectionTitle(String title) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: Text(
        title,
        style: const TextStyle(fontSize: 16, fontWeight: FontWeight.bold),
      ),
    );
  }

  // Widget utilitaire : carte d'affichage du statut
  Widget _buildStatusCard(String text) {
    return Container(
      margin: const EdgeInsets.only(bottom: 8),
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: Colors.grey.shade100,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: Colors.grey.shade300),
      ),
      child: Text(text, style: const TextStyle(fontFamily: 'monospace')),
    );
  }
}