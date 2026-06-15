import 'package:flutter/material.dart';
import 'package:firebase_core/firebase_core.dart';
import 'package:firebase_app_check/firebase_app_check.dart';
import 'package:safe_device/safe_device.dart';
import 'package:http/http.dart' as http;
import 'firebase_options.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();

  // 1. Firebase
  await Firebase.initializeApp(
    options: DefaultFirebaseOptions.currentPlatform,
  );

  // 2. AppCheck
  await FirebaseAppCheck.instance.activate(
    androidProvider: AndroidProvider.debug,
  );

  // 3. Root detection
  bool isRooted = await SafeDevice.isJailBroken;
  print('Appareil rooté : $isRooted');

  // 4. Récupérer token AppCheck
  String? token = await FirebaseAppCheck.instance.getToken();
  print('Token : $token');

  // 5. Appeler Spring Boot
  final response = await http.get(
    Uri.parse('http://10.0.2.2:8080/api/security/hello'),
    headers: {
      'X-Firebase-AppCheck': token ?? '',
    },
  );
  print('Réponse : ${response.body}');

  runApp(MyApp(isRooted: isRooted));
}






class MyApp extends StatelessWidget {
  final bool isRooted;

  const MyApp({super.key, required this.isRooted});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Security SDK Demo',
      home: Scaffold(
        appBar: AppBar(
          title: const Text('Security SDK Demo'),
          backgroundColor: Colors.deepPurple,
        ),
        body: Padding(
          padding: const EdgeInsets.all(20),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              _buildStatusCard(
                icon: '🔥',
                title: 'Firebase',
                status: 'Initialisé',
                isOk: true,
              ),
              const SizedBox(height: 16),
              _buildStatusCard(
                icon: '🛡️',
                title: 'AppCheck',
                status: 'Actif (mode debug)',
                isOk: true,
              ),
              const SizedBox(height: 16),
              _buildStatusCard(
                icon: '📱',
                title: 'Appareil',
                status: isRooted ? 'Compromis ' : 'Sécurisé ',
                isOk: !isRooted,
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildStatusCard({
    required String icon,
    required String title,
    required String status,
    required bool isOk,
  }) {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: isOk ? Colors.green.shade50 : Colors.red.shade50,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(
          color: isOk ? Colors.green : Colors.red,
        ),
      ),
      child: Row(
        children: [
          Text(icon, style: const TextStyle(fontSize: 32)),
          const SizedBox(width: 16),
          Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                title,
                style: const TextStyle(
                  fontSize: 18,
                  fontWeight: FontWeight.bold,
                ),
              ),
              Text(
                status,
                style: TextStyle(
                  fontSize: 14,
                  color: isOk ? Colors.green : Colors.red,
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }
}