import 'package:flutter/material.dart';
import 'package:cryptography/cryptography.dart';
import 'package:bcrypt/bcrypt.dart';
import 'constants.dart';
import 'secure_chat_service.dart';
import 'secure_chat_screen.dart';

// --- ЭКРАН: ВХОД И РЕГИСТРАЦИЯ (AuthScreen) ---

class AuthScreen extends StatefulWidget {
  const AuthScreen({super.key});

  @override
  State<AuthScreen> createState() => _AuthScreenState();
}

class _AuthScreenState extends State<AuthScreen> {
  // Контроллеры для ввода паролей
  final _alicePasswordController = TextEditingController();
  final _bobPasswordController = TextEditingController();

  User _selectedUser = User.Alice; // Определяет, кто будет активным пользователем в чате
  bool _isAuthSetupComplete = false;
  bool _isLoading = false;

  // Сервисы для Алисы и Боба
  final _aliceService = SecureChatService();
  final _bobService = SecureChatService();

  // Публичные ключи для обмена
  PublicKey? aliceECDHPublicKey;
  PublicKey? bobECDHPublicKey;
  PublicKey? aliceSigningPublicKey;
  PublicKey? bobSigningPublicKey;

  @override
  void dispose() {
    _alicePasswordController.dispose();
    _bobPasswordController.dispose();
    super.dispose();
  }

  // Функция входа и настройки E2EE
  Future<void> _loginAndSetupChat() async {
    final alicePassword = _alicePasswordController.text;
    final bobPassword = _bobPasswordController.text;

    if (alicePassword.isEmpty || bobPassword.isEmpty) {
      _showSnackBar('❌ Пожалуйста, введите пароли для Алисы и Боба.');
      return;
    }

    setState(() {
      _isLoading = true;
      _isAuthSetupComplete = false;
    });

    try {
      // 1. Инициализация/Вход Алисы с ее паролем (регистрация при первом входе)
      aliceECDHPublicKey = await _aliceService.initializeOrLoginUser(
        alicePassword,
        ALICE_ECDH_KEY,
        ALICE_SIGN_KEY,
      );
      aliceSigningPublicKey = _aliceService.signingPublicKey;

      // 2. Инициализация/Вход Боба с его паролем (регистрация при первом входе)
      bobECDHPublicKey = await _bobService.initializeOrLoginUser(
        bobPassword,
        BOB_ECDH_KEY,
        BOB_SIGN_KEY,
      );
      bobSigningPublicKey = _bobService.signingPublicKey;

      // 3. Обмен ключами (ECDH) для создания общего секрета
      await _aliceService.setupChat(ALICE_ECDH_KEY, ALICE_SIGN_KEY, bobECDHPublicKey!);
      await _bobService.setupChat(BOB_ECDH_KEY, BOB_SIGN_KEY, aliceECDHPublicKey!);

      // Установка флага, что криптографический сеанс готов
      _isAuthSetupComplete = true;

      _showSnackBar('✅ E2EE сеанс готов. Вход выполнен как ${_selectedUser.name}.');
      _loginAsUser(); // Переход на экран чата

    } catch (e) {
      _showSnackBar('❌ Ошибка криптографии/пароля: Неверный пароль или ошибка инициализации: ${e.toString()}');
      _isAuthSetupComplete = false;
    } finally {
      if(mounted) {
        setState(() {
          _isLoading = false;
        });
      }
    }
  }

  // Функция перехода на экран чата
  void _loginAsUser() {
    if (!_isAuthSetupComplete || !mounted) return;

    // Переход к экрану чата
    Navigator.pushReplacement(
      context,
      MaterialPageRoute(
        builder: (context) => SecureChatScreen(
          currentSender: _selectedUser,
          aliceService: _aliceService,
          bobService: _bobService,
          // Публичные ключи передаются для проверки подписей
          aliceSigningPublicKey: aliceSigningPublicKey!,
          bobSigningPublicKey: bobSigningPublicKey!,
        ),
      ),
    );
  }

  void _showSnackBar(String message) {
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text(message)),
    );
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Scaffold(
      backgroundColor: theme.colorScheme.surface,
      appBar: AppBar(
        title: const Text("Secure Chat Login"),
        backgroundColor: theme.colorScheme.primary,
        foregroundColor: theme.colorScheme.onPrimary,
        elevation: 8, // Более выраженная тень
      ),
      body: Center(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(32.0),
          child: Card(
            elevation: 8, // Карточка с тенью для лучшей изоляции формы
            shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(20)),
            color: theme.colorScheme.surface,
            child: Padding(
              padding: const EdgeInsets.all(32.0),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                mainAxisAlignment: MainAxisAlignment.center,
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  Text(
                    "🔐 Secure Key Setup",
                    style: theme.textTheme.headlineLarge?.copyWith(
                      color: theme.colorScheme.primary,
                      fontWeight: FontWeight.w900,
                    ),
                    textAlign: TextAlign.center,
                  ),
                  const SizedBox(height: 16),

                  const Text(
                    'Ваш пароль используется для шифрования приватных ключей E2EE (PBE). При первом входе ключи генерируются.',
                    textAlign: TextAlign.center,
                    style: TextStyle(fontStyle: FontStyle.italic, color: Colors.grey),
                  ),
                  const SizedBox(height: 40),

                  // --- ПОЛЕ ПАРОЛЯ АЛИСЫ ---
                  TextField(
                    controller: _alicePasswordController,
                    obscureText: true,
                    decoration: InputDecoration(
                      labelText: 'Пароль для Алисы (Alice)',
                      prefixIcon: Icon(Icons.person, color: Colors.pink.shade300),
                    ),
                  ),
                  const SizedBox(height: 24),

                  // --- ПОЛЕ ПАРОЛЯ БОБА ---
                  TextField(
                    controller: _bobPasswordController,
                    obscureText: true,
                    decoration: InputDecoration(
                      labelText: 'Пароль для Боба (Bob)',
                      prefixIcon: Icon(Icons.person_2, color: Colors.blue.shade300),
                    ),
                  ),
                  const SizedBox(height: 40),

                  // --- ВЫБОР ПОЛЬЗОВАТЕЛЯ ---
                  Row(
                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                    children: [
                      Text("Войти как: ", style: theme.textTheme.titleLarge),
                      DropdownButton<User>(
                        value: _selectedUser,
                        items: User.values.map((User user) {
                          return DropdownMenuItem<User>(
                            value: user,
                            child: Text(
                              user.name,
                              style: TextStyle(
                                fontWeight: FontWeight.bold,
                                color: user == User.Alice ? Colors.pink.shade700 : Colors.blue.shade700,
                              ),
                            ),
                          );
                        }).toList(),
                        onChanged: (User? newValue) {
                          if (newValue != null) {
                            setState(() {
                              _selectedUser = newValue;
                            });
                          }
                        },
                      ),
                    ],
                  ),
                  const SizedBox(height: 48),

                  // --- КНОПКА ВХОДА И НАСТРОЙКИ ---
                  _isLoading
                      ? Column(
                    children: [
                      CircularProgressIndicator(color: theme.colorScheme.primary),
                      const SizedBox(height: 16),
                      Text(
                        'Инициализация E2EE и вход...',
                        style: TextStyle(color: theme.colorScheme.primary),
                      ),
                    ],
                  )
                      : ElevatedButton.icon(
                    onPressed: _loginAndSetupChat,
                    icon: const Icon(Icons.vpn_key),
                    label: Text('Войти как ${_selectedUser.name}'),
                    style: ElevatedButton.styleFrom(
                      backgroundColor: theme.colorScheme.primary,
                      foregroundColor: theme.colorScheme.onPrimary,
                      elevation: 8,
                    ),
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}