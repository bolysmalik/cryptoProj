// lib/main.dart (Интерактивный Чат - ИСПРАВЛЕННЫЙ)
import 'package:flutter/material.dart';
import 'secure_chat_service.dart';
import 'package:cryptography/cryptography.dart';
import 'package:bcrypt/bcrypt.dart'; // Используем BCrypt
// import 'my_own_sha256.dart'; // Примитив "с нуля" для презентации

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
  User _currentSender = User.Alice; // Отправитель по умолчанию
  bool _isInitialized = false;

  // Публичные ключи для обмена
  PublicKey? alicePubKey;
  PublicKey? bobPubKey;

  @override
  void initState() {
    super.initState();
    _initializeKeysAndChat();
  }

  // --- 1. ИНИЦИАЛИЗАЦИЯ И НАСТРОЙКА КЛЮЧЕЙ (ВЫПОЛНЯЕТСЯ ОДИН РАЗ) ---
  Future<void> _initializeKeysAndChat() async {
    _addSystemMessage('Инициализация...');

    // 1. Симуляция регистрации и хеширования пароля (bcrypt)
    // ИСПРАВЛЕНИЕ ОШИБКИ ROUNDS: Используем BCrypt.gensalt() без аргументов
    final salt = BCrypt.gensalt();
    BCrypt.hashpw('secure_password_123', salt);

    // 2. Генерация ключей и сохранение их в Secure Storage
    final aliceKeyPair = await _aliceService.initializeUser(ALICE_PRIV_KEY);
    final bobKeyPair = await _bobService.initializeUser(BOB_PRIV_KEY);
    alicePubKey = await aliceKeyPair.extractPublicKey();
    bobPubKey = await bobKeyPair.extractPublicKey();

    // 3. Обмен публичными ключами и установка общего секрета (ECDH)
    await _aliceService.setupChat(ALICE_PRIV_KEY, bobPubKey!);
    await _bobService.setupChat(BOB_PRIV_KEY, alicePubKey!);

    setState(() {
      _isInitialized = true;
      _addSystemMessage('✅ Чат между Алисой и Бобом готов к работе!');
    });
  }

  // --- 2. ЛОГИКА ОТПРАВКИ И ПОЛУЧЕНИЯ СООБЩЕНИЯ ---
  void _sendMessage() async {
    if (!_isInitialized || _messageController.text.isEmpty) return;

    final plaintext = _messageController.text;
    final senderService = _currentSender == User.Alice ? _aliceService : _bobService;
    final recipientService = _currentSender == User.Alice ? _bobService : _aliceService;
    final senderPubKey = _currentSender == User.Alice ? alicePubKey! : bobPubKey!;

    _messageController.clear();

    try {
      // 1. ОТПРАВКА: Шифрование и Подпись
      final encryptedMessage = await senderService.encryptAndSign(plaintext);
      final ciphertextPreview = encryptedMessage.ciphertext.sublist(0, 10).map((e) => e.toRadixString(16).padLeft(2, '0')).join('');

      _addMessage(_currentSender, plaintext, '🔒 Зашифровано и Подписано: $ciphertextPreview...');

      // 2. ПОЛУЧЕНИЕ: Проверка и Дешифрование
      final decryptedMessage = await recipientService.decryptAndVerify(encryptedMessage, senderPubKey);

      _addSystemMessage('Проверено и Расшифровано Получателем (${recipientService == _aliceService ? 'Алиса' : 'Боб'}): "$decryptedMessage"');

    } catch (e) {
      _addSystemMessage('❌ Ошибка безопасности при отправке: $e');
    }

    // Прокрутка вниз
    _scrollController.animateTo(
      _scrollController.position.maxScrollExtent,
      duration: const Duration(milliseconds: 300),
      curve: Curves.easeOut,
    );
  }

  // --- 3. UI И МЕТОДЫ ПОМОЩНИКИ ---
  void _addMessage(User sender, String plaintext, String status) {
    setState(() {
      _messages.add({
        'user': sender.name,
        'text': plaintext,
        'status': status,
      });
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
        title: const Text('Secure Messaging Demo (E2EE)'),
        backgroundColor: Colors.blueGrey,
        actions: [
          // Переключатель отправителя
          DropdownButton<User>(
            value: _currentSender,
            onChanged: (User? newValue) {
              if (newValue != null) {
                setState(() {
                  _currentSender = newValue;
                  _addSystemMessage('Отправитель переключен на: ${_currentSender.name}');
                });
              }
            },
            items: User.values.map<DropdownMenuItem<User>>((User value) {
              return DropdownMenuItem<User>(
                value: value,
                child: Text('Отправить как ${value.name}'),
              );
            }).toList(),
          ),
          const SizedBox(width: 16),
        ],
      ),
      body: Column(
        children: <Widget>[
          // Область сообщений
          Expanded(
            child: ListView.builder(
              controller: _scrollController,
              padding: const EdgeInsets.all(8.0),
              itemCount: _messages.length,
              itemBuilder: (context, index) {
                final message = _messages[index];
                if (message['user'] == 'System') {
                  return ListTile(
                    title: Text(message['text']!, style: const TextStyle(color: Colors.red, fontStyle: FontStyle.italic)),
                  );
                }

                final isAlice = message['user'] == User.Alice.name;

                return Align(
                  alignment: isAlice ? Alignment.centerRight : Alignment.centerLeft,
                  child: Padding(
                    padding: const EdgeInsets.symmetric(vertical: 4.0),
                    child: Column(
                      crossAxisAlignment: isAlice ? CrossAxisAlignment.end : CrossAxisAlignment.start,
                      children: [
                        Container(
                          padding: const EdgeInsets.all(12),
                          decoration: BoxDecoration(
                            color: isAlice ? Colors.blue[100] : Colors.green[100],
                            borderRadius: BorderRadius.circular(15),
                          ),
                          child: Text(
                            message['text']!,
                            style: const TextStyle(fontSize: 16),
                          ),
                        ),
                        // Статус шифрования/подписи
                        Text(
                          '${message['user']}: ${message['status']}',
                          style: TextStyle(fontSize: 10, color: Colors.grey[600]),
                        ),
                      ],
                    ),
                  ),
                );
              },
            ),
          ),

          // Поле ввода и кнопка отправки
          Padding(
            padding: const EdgeInsets.all(8.0),
            child: Row(
              children: <Widget>[
                Expanded(
                  child: TextField(
                    controller: _messageController,
                    decoration: InputDecoration(
                      hintText: "Сообщение для ${( _currentSender == User.Alice ? 'Боба' : 'Алисы')}...",
                      border: const OutlineInputBorder(),
                    ),
                    onSubmitted: (_) => _sendMessage(),
                  ),
                ),
                const SizedBox(width: 8.0),
                FloatingActionButton(
                  onPressed: _isInitialized ? _sendMessage : null,
                  backgroundColor: _isInitialized ? Colors.blueGrey : Colors.grey,
                  child: const Icon(Icons.send),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}