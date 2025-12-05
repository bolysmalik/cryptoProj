// lib/main.dart (Финальная рабочая версия)

import 'package:flutter/material.dart';
import 'package:cryptography/cryptography.dart';
import 'package:bcrypt/bcrypt.dart';
// Импортируем сервис и новые константы
import 'secure_chat_service.dart';


void main() => runApp(const MyApp());

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return const MaterialApp(
      title: 'Secure Messaging App',
      home: SecureChatScreen(),
    );
  }
}

enum User { Alice, Bob }

class SecureChatScreen extends StatefulWidget {
  const SecureChatScreen({super.key});

  @override
  State<SecureChatScreen> createState() => _SecureChatScreenState();
}

class _SecureChatScreenState extends State<SecureChatScreen> {
  final _messageController = TextEditingController();
  final _scrollController = ScrollController();

  // Сервисы для двух пользователей
  final _aliceService = SecureChatService();
  final _bobService = SecureChatService();

  // Состояние чата
  List<Map<String, String>> _messages = [];
  User _currentSender = User.Alice;
  bool _isInitialized = false;

  // ⚠️ ДВЕ ГРУППЫ ПУБЛИЧНЫХ КЛЮЧЕЙ:
  PublicKey? aliceECDHPublicKey; // X25519 для обмена ключами
  PublicKey? bobECDHPublicKey;
  PublicKey? aliceSigningPublicKey; // Ed25519 для проверки подписи
  PublicKey? bobSigningPublicKey;

  @override
  void initState() {
    super.initState();
    _initializeKeysAndChat();
  }

  // --- 1. ИНИЦИАЛИЗАЦИЯ И НАСТРОЙКА КЛЮЧЕЙ ---
  Future<void> _initializeKeysAndChat() async {
    _addSystemMessage("Инициализация E2EE...");

    // 1. Симуляция хеширования пароля (bcrypt)
    final salt = BCrypt.gensalt();
    BCrypt.hashpw('secure_password_123', salt);

    // 2. Генерация ключей и сохранение (ECDH и Ed25519 для каждого)
    // initializeUser возвращает ECDH Public Key, а ключ подписи сохраняется в сервисе
    aliceECDHPublicKey = await _aliceService.initializeUser(ALICE_ECDH_KEY, ALICE_SIGN_KEY);
    bobECDHPublicKey = await _bobService.initializeUser(BOB_ECDH_KEY, BOB_SIGN_KEY);

    // 3. Получение публичных ключей Ed25519 для проверки подписи
    aliceSigningPublicKey = _aliceService.signingPublicKey;
    bobSigningPublicKey = _bobService.signingPublicKey;

    // 4. Обмен ключами (ECDH)
    await _aliceService.setupChat(ALICE_ECDH_KEY, ALICE_SIGN_KEY, bobECDHPublicKey!);
    await _bobService.setupChat(BOB_ECDH_KEY, BOB_SIGN_KEY, aliceECDHPublicKey!);

    setState(() {
      _isInitialized = true;
    });

    _addSystemMessage("✅ Чат между Алисой и Бобом готов (ECDH + AES + Ed25519)");
  }

  // --- 2. ЛОГИКА ОТПРАВКИ И ПОЛУЧЕНИЯ СООБЩЕНИЯ ---
  void _sendMessage() async {
    if (!_isInitialized || _messageController.text.isEmpty) return;

    final text = _messageController.text.trim();
    _messageController.clear();

    final sender = _currentSender == User.Alice ? _aliceService : _bobService;
    final receiver = _currentSender == User.Alice ? _bobService : _aliceService;

    // ⚠️ ВАЖНО: Используем ПУБЛИЧНЫЙ КЛЮЧ ПОДПИСИ ОТПРАВИТЕЛЯ (Ed25519)
    final senderSigningKey = _currentSender == User.Alice ? aliceSigningPublicKey! : bobSigningPublicKey!;
    final receiverName = _currentSender == User.Alice ? "Боб" : "Алиса";

    try {
      // 1. ОТПРАВКА: Шифрование и Подпись
      final encrypted = await sender.encryptAndSign(text);

      final hexPreview = encrypted.ciphertext
          .take(10)
          .map((b) => b.toRadixString(16).padLeft(2, '0'))
          .join('');

      _addMessage(_currentSender, text, "🔐 Encrypted: $hexPreview...");

      // 2. ПОЛУЧЕНИЕ: Проверка Подписи и Дешифрование
      final decrypted = await receiver.decryptAndVerify(encrypted, senderSigningKey);

      _addSystemMessage("📩 ($receiverName получил): $decrypted");

    } catch (err) {
      _addSystemMessage("❌ Ошибка безопасности: $err");
    }

    Future.delayed(const Duration(milliseconds: 200), () {
      _scrollController.animateTo(
        _scrollController.position.maxScrollExtent,
        duration: const Duration(milliseconds: 300),
        curve: Curves.easeOut,
      );
    });
  }

  // --- 3. UI И МЕТОДЫ ПОМОЩНИКИ ---
  void _addMessage(User sender, String text, String status) {
    setState(() {
      _messages.add({'user': sender.name, 'text': text, 'status': status});
    });
  }

  void _addSystemMessage(String text) {
    setState(() {
      _messages.add({'user': 'System', 'text': text, 'status': ''});
    });
  }

  @override
  void dispose() {
    _messageController.dispose();
    _scrollController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text("Secure Messaging Demo (E2EE)"),
        backgroundColor: Colors.blueGrey,
        actions: [
          DropdownButton<User>(
            value: _currentSender,
            onChanged: (v) {
              if (v != null) {
                setState(() {
                  _currentSender = v;
                });
                _addSystemMessage("Отправитель: ${v.name}");
              }
            },
            items: User.values.map((u) {
              return DropdownMenuItem(
                value: u,
                child: Text("Отправить как ${u.name}"),
              );
            }).toList(),
          ),
          const SizedBox(width: 16),
        ],
      ),
      body: Column(
        children: [
          Expanded(
            child: ListView.builder(
              controller: _scrollController,
              padding: const EdgeInsets.all(8),
              itemCount: _messages.length,
              itemBuilder: (context, index) {
                final msg = _messages[index];
                if (msg['user'] == 'System') {
                  return Padding(
                    padding: const EdgeInsets.all(6),
                    child: Text(
                      msg['text']!,
                      style: const TextStyle(
                        color: Colors.red,
                        fontStyle: FontStyle.italic,
                      ),
                    ),
                  );
                }
                final isAlice = msg['user'] == User.Alice.name;
                return Align(
                  alignment: isAlice ? Alignment.centerRight : Alignment.centerLeft,
                  child: Padding(
                    padding: const EdgeInsets.symmetric(vertical: 6),
                    child: Column(
                      crossAxisAlignment:
                      isAlice ? CrossAxisAlignment.end : CrossAxisAlignment.start,
                      children: [
                        Container(
                          padding: const EdgeInsets.all(12),
                          decoration: BoxDecoration(
                            color: isAlice ? Colors.blue[100] : Colors.green[100],
                            borderRadius: BorderRadius.circular(15),
                          ),
                          child: Text(msg['text']!),
                        ),
                        Text(
                          "${msg['user']}: ${msg['status']}",
                          style: const TextStyle(fontSize: 10, color: Colors.grey),
                        ),
                      ],
                    ),
                  ),
                );
              },
            ),
          ),
          Padding(
            padding: const EdgeInsets.all(8),
            child: Row(
              children: [
                Expanded(
                  child: TextField(
                    controller: _messageController,
                    decoration: InputDecoration(
                      hintText:
                      "Сообщение для ${_currentSender == User.Alice ? 'Боба' : 'Алисы'}...",
                      border: const OutlineInputBorder(),
                    ),
                    onSubmitted: (_) => _sendMessage(),
                  ),
                ),
                const SizedBox(width: 8),
                FloatingActionButton(
                  backgroundColor:
                  _isInitialized ? Colors.blueGrey : Colors.grey,
                  onPressed: _isInitialized ? _sendMessage : null,
                  child: const Icon(Icons.send),
                ),
              ],
            ),
          )
        ],
      ),
    );
  }
}