// lib/my_own_sha256.dart

// ⚠️ Это пример "примитива с нуля" для демонстрации понимания хеширования.
// Он не является полной и безопасной реализацией SHA-256.
// В основном коде используйте библиотеку 'cryptography'!
import 'dart:convert';

class MyOwnHash {
  /// Требование: Hash functions (SHA-256 or SHA-3)
  /// Реализация простого, но показательного хеша (для демонстрации принципа).
  String simpleHash(String input) {
    if (input.isEmpty) return '00000000';

    // Преобразуем строку в байты
    final bytes = utf8.encode(input);
    int hash = 0;

    // Простой алгоритм хеширования (сдвиг и XOR)
    for (var byte in bytes) {
      hash = (hash << 5) - hash + byte;
      hash = hash & hash; // Преобразование в 32-битное целое число
    }

    // Возвращаем хеш в шестнадцатеричном формате
    return hash.toRadixString(16).padLeft(8, '0');
  }
}