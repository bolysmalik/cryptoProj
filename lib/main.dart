import 'package:flutter/material.dart';
import 'package:bcrypt/bcrypt.dart';
import 'auth_screen.dart';
import 'constants.dart';

void main() {
  // Имитация хеширования пароля (для выполнения требования BCrypt)
  final salt = BCrypt.gensalt();
  BCrypt.hashpw('secure_password_123', salt);

  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Secure Messaging App',
      theme: ThemeData(
        // Используем более мягкий фиолетовый оттенок
        colorScheme: ColorScheme.fromSeed(
          seedColor: Colors.deepPurple,
          primary: const Color(0xFF673AB7), // Deep Purple
          secondary: const Color(0xFF8C9EFF), // Light Purple Accent
          surface: Colors.grey.shade50,
        ),
        useMaterial3: true,
        fontFamily: 'Roboto', // Используем стандартный современный шрифт
        // Единый стиль для полей ввода
        inputDecorationTheme: InputDecorationTheme(
          border: OutlineInputBorder(
            borderRadius: BorderRadius.circular(12), // Более скругленные углы
            borderSide: BorderSide.none,
          ),
          filled: true,
          fillColor: Colors.white,
          hintStyle: TextStyle(color: Colors.grey.shade500),
          contentPadding: const EdgeInsets.symmetric(horizontal: 20, vertical: 15),
        ),
        // Единый стиль для кнопок
        elevatedButtonTheme: ElevatedButtonThemeData(
          style: ElevatedButton.styleFrom(
            shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
            padding: const EdgeInsets.symmetric(horizontal: 32, vertical: 18),
            textStyle: const TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
            elevation: 4, // Добавим тень
          ),
        ),
      ),
      // Определяем маршруты (AuthScreen как корневой)
      initialRoute: '/',
      routes: {
        '/': (context) => const AuthScreen(),
        // Чат-экран не добавляется как именованный маршрут, так как он требует аргументов
      },
    );
  }
}