import 'package:flutter/material.dart';
import 'package:cryptography/cryptography.dart';
import 'constants.dart';
import 'secure_chat_service.dart';

// --- ЭКРАН ЧАТА (SecureChatScreen) ---

class SecureChatScreen extends StatefulWidget {
  final User currentSender;
  final SecureChatService aliceService;
  final SecureChatService bobService;

  final PublicKey aliceSigningPublicKey;
  final PublicKey bobSigningPublicKey;

  const SecureChatScreen({
    super.key,
    required this.currentSender,
    required this.aliceService,
    required this.bobService,
    required this.aliceSigningPublicKey,
    required this.bobSigningPublicKey,
  });

  @override
  State<SecureChatScreen> createState() => _SecureChatScreenState();
}

class _SecureChatScreenState extends State<SecureChatScreen> {
  final _messageController = TextEditingController();
  final _scrollController = ScrollController();

  List<Map<String, String>> _messages = [];
  late User _currentSender;
  bool _isInitialized = true;

  @override
  void initState() {
    super.initState();
    _currentSender = widget.currentSender;

    // Загружаем сохраненные сообщения при входе
    _messages = List.from(MessageStorage.messages);

    _addSystemMessage("✅ Чат между Алисой и Бобом готов (Вход выполнен как ${_currentSender.name})");
  }

  // --- ЛОГИКА ОТПРАВКИ И ПОЛУЧЕНИЯ СООБЩЕНИЯ ---
  void _sendMessage() async {
    if (!_isInitialized || _messageController.text.isEmpty) return;

    final text = _messageController.text.trim();
    _messageController.clear();

    // Отправитель и Получатель
    final sender = _currentSender == User.Alice ? widget.aliceService : widget.bobService;
    final receiver = _currentSender == User.Alice ? widget.bobService : widget.aliceService;

    // Публичный ключ подписи отправителя (для проверки на стороне получателя)
    final senderSigningKey = _currentSender == User.Alice ? widget.aliceSigningPublicKey : widget.bobSigningPublicKey;
    final receiverName = _currentSender == User.Alice ? "Боб" : "Алиса";

    try {
      // 1. Шифрование и Подпись
      final encrypted = await sender.encryptAndSign(text);

      final hexPreview = encrypted.ciphertext
          .take(10)
          .map((b) => b.toRadixString(16).padLeft(2, '0'))
          .join('');

      // Данные для сохранения и отображения
      final messageData = {
        'user': _currentSender.name,
        'text': text,
        'status': "🔐 Encrypted: $hexPreview..."
      };

      _addMessage(messageData); // Добавляем в локальный список
      MessageStorage.messages.add(messageData); // Сохраняем в персистентное хранилище

      // 2. Дешифрование и Проверка Подписи
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

  // --- ЛОГИКА ВЫХОДА И СМЕНЫ ПОЛЬЗОВАТЕЛЯ ---
  void _logout() {
    if (!mounted) return;

    // Сбрасываем сервисы (ключи удаляются из памяти)
    widget.aliceService.resetKeys();
    widget.bobService.resetKeys();

    // Загружаем экран аутентификации
    Navigator.pushReplacementNamed(context, '/');
  }

  // --- МЕТОДЫ ПОМОЩНИКИ И UI ---
  void _addMessage(Map<String, String> message) {
    setState(() {
      _messages.add(message);
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
    final theme = Theme.of(context);
    // Цвета для Алисы и Боба
    final aliceColor = Colors.pink.shade300;
    final bobColor = Colors.blue.shade300;

    return Scaffold(
      backgroundColor: theme.colorScheme.surface,
      appBar: AppBar(
        title: Text("Secure Chat as ${_currentSender.name}"),
        backgroundColor: theme.colorScheme.primary,
        foregroundColor: theme.colorScheme.onPrimary,
        elevation: 8,
        actions: [
          IconButton(
            icon: const Icon(Icons.logout),
            tooltip: 'Выйти / Сменить пользователя',
            onPressed: _logout,
          ),
          const SizedBox(width: 8),
        ],
      ),
      body: Column(
        children: [
          Expanded(
            child: ListView.builder(
              controller: _scrollController,
              padding: const EdgeInsets.all(12),
              itemCount: _messages.length,
              itemBuilder: (context, index) {
                final msg = _messages[index];
                final isAlice = msg['user'] == User.Alice.name;
                final isSystem = msg['user'] == 'System';

                if (isSystem) {
                  return Center(
                    child: Padding(
                      padding: const EdgeInsets.symmetric(vertical: 8.0),
                      child: Container(
                        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
                        decoration: BoxDecoration(
                          color: Colors.deepPurple.shade50, // Более красивый системный цвет
                          borderRadius: BorderRadius.circular(15),
                        ),
                        child: Text(
                          msg['text']!,
                          textAlign: TextAlign.center,
                          style: TextStyle(
                            color: Colors.deepPurple.shade700,
                            fontStyle: FontStyle.italic,
                            fontSize: 12,
                          ),
                        ),
                      ),
                    ),
                  );
                }

                // Логика определения текущего отправителя и выравнивания
                final isMe = msg['user'] == _currentSender.name;

                return Align(
                  alignment: isMe ? Alignment.centerRight : Alignment.centerLeft,
                  child: Padding(
                    padding: const EdgeInsets.symmetric(vertical: 4),
                    child: Column(
                      crossAxisAlignment: isMe ? CrossAxisAlignment.end : CrossAxisAlignment.start,
                      children: [
                        // Имя пользователя (только для собеседника)
                        if (!isMe)
                          Padding(
                            padding: const EdgeInsets.only(bottom: 2, left: 8, right: 8),
                            child: Text(
                              msg['user']!,
                              style: TextStyle(
                                fontSize: 12,
                                fontWeight: FontWeight.bold,
                                color: isAlice ? aliceColor : bobColor,
                              ),
                            ),
                          ),
                        Container(
                          constraints: BoxConstraints(maxWidth: MediaQuery.of(context).size.width * 0.75),
                          padding: const EdgeInsets.all(12),
                          decoration: BoxDecoration(
                            // Цвет зависит от того, это я или собеседник
                            color: isMe
                                ? theme.colorScheme.primary.withOpacity(0.9) // Мои сообщения - основной цвет
                                : theme.colorScheme.secondary.withOpacity(0.9), // Сообщения собеседника - акцентный
                            borderRadius: BorderRadius.only(
                              topLeft: const Radius.circular(20),
                              topRight: const Radius.circular(20),
                              bottomLeft: isMe ? const Radius.circular(20) : const Radius.circular(4),
                              bottomRight: isMe ? const Radius.circular(4) : const Radius.circular(20),
                            ),
                            boxShadow: [
                              BoxShadow(
                                color: Colors.black.withOpacity(0.2),
                                blurRadius: 4,
                                offset: const Offset(0, 2),
                              ),
                            ],
                          ),
                          child: Text(
                            msg['text']!,
                            style: TextStyle(
                              color: isMe ? theme.colorScheme.onPrimary : Colors.black87,
                              fontSize: 15,
                            ),
                          ),
                        ),
                        Padding(
                          padding: const EdgeInsets.only(top: 4, right: 8, left: 8),
                          child: Text(
                            isMe ? "Вы: ${msg['status']}" : "Получено: ${msg['status']}",
                            style: const TextStyle(fontSize: 10, color: Colors.grey, fontStyle: FontStyle.italic),
                          ),
                        ),
                      ],
                    ),
                  ),
                );
              },
            ),
          ),
          // --- ПОЛЕ ВВОДА СООБЩЕНИЯ ---
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: theme.colorScheme.surface,
              boxShadow: [
                BoxShadow(
                  color: Colors.black.withOpacity(0.1),
                  blurRadius: 10,
                  offset: const Offset(0, -5),
                ),
              ],
            ),
            child: Row(
              children: [
                Expanded(
                  child: TextField(
                    controller: _messageController,
                    decoration: InputDecoration(
                      hintText: "Сообщение для ${_currentSender == User.Alice ? 'Боба' : 'Алисы'}...",
                      border: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(30),
                        borderSide: BorderSide.none,
                      ),
                      filled: true,
                      fillColor: Colors.grey.shade200, // Более светлый фон
                      contentPadding: const EdgeInsets.symmetric(horizontal: 20, vertical: 10),
                    ),
                    onSubmitted: (_) => _sendMessage(),
                  ),
                ),
                const SizedBox(width: 8),
                FloatingActionButton(
                  // Используем основной цвет темы
                  backgroundColor: theme.colorScheme.primary,
                  foregroundColor: theme.colorScheme.onPrimary,
                  onPressed: _isInitialized ? _sendMessage : null,
                  elevation: 4,
                  shape: const CircleBorder(),
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