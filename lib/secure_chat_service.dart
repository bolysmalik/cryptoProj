import 'dart:convert';
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';
import 'package:bcrypt/bcrypt.dart';
import 'package:flutter/foundation.dart';

class _KeyStorageMock {
  static final Map<String, String> _storage = {};

  Future<String?> read({required String key}) async {
    return _storage[key];
  }

  Future<void> write(
      {required String key, required String value}) async {
    _storage[key] = value;
  }

  Future<bool> containsKey({required String key}) async {
    return _storage.containsKey(key);
  }
}

// Дополнительные ключи для PBE (Password-Based Encryption)
const PBKDF2_SALT_PREFIX = 'pbe_salt_';
const PASS_HASH_PREFIX = 'pass_hash_';

class SecureChatService {
  final _storage = _KeyStorageMock();

  final _x25519 = X25519();
  final _ecdsa = Ed25519();

  final _aesGcm = AesGcm.with256bits();

  final _kdf = Pbkdf2(
    macAlgorithm: Hmac.sha256(),
    iterations: 100000,
    bits: 256,
  );

  final _keyEncryptionCipher = AesGcm.with256bits();

  // --- СОСТОЯНИЕ КЛЮЧЕЙ ---
  SimpleKeyPair? _ecdhKeyPair;
  SimpleKeyPair? _signingKeyPair;
  SecretKey? sharedSecret;

  PublicKey? remoteECDHPublicKey;
  PublicKey? signingPublicKey;
  String? _userAlias;

  // --- ХЕЛПЕРЫ ДЛЯ ХРАНЕНИЯ SECRETBOX (JSON) ---

  /// Кодирует SecretBox в строку JSON для хранения
  String _encodeSecretBox(SecretBox box) {
    final map = {
      'ciphertext': base64.encode(box.cipherText),
      'nonce': base64.encode(box.nonce),
      'mac': base64.encode(box.mac.bytes),
    };
    return json.encode(map);
  }

  /// Декодирует SecretBox из строки JSON
  SecretBox _decodeSecretBox(String encoded) {
    final map = json.decode(encoded) as Map<String, dynamic>;
    return SecretBox(
      base64.decode(map['ciphertext'] as String),
      nonce: base64.decode(map['nonce'] as String),
      mac: Mac(base64.decode(map['mac'] as String)),
    );
  }

  // --- МЕТОДЫ PBE И УПРАВЛЕНИЯ КЛЮЧАМИ ---

  /// Генерация ключа из пароля (Key Derivation Function)
  Future<SecretKey> _deriveKeyFromPassword(String password, List<int> salt) async {
    final passwordBytes = utf8.encode(password);
    // Вызываем deriveKey, который ожидает SecretKey, созданный из байтов пароля.
    return await _kdf.deriveKey(
      secretKey: SecretKey(passwordBytes),
      nonce: salt,
    );
  }

  /// Шифрует два приватных ключа с использованием KEK (ключа, полученного из пароля)
  Future<void> _encryptAndStoreKeys(String password, String ecdhKeyAlias, String signingKeyAlias) async {
    // 1. Генерируем новый Salt (nonce для AesGcm)
    final saltList = _keyEncryptionCipher.newNonce().toList();

    // 2. Получаем KEK (Key Encryption Key) из пароля и соли
    final kek = await _deriveKeyFromPassword(password, saltList);

    // 3. Шифруем приватные ключи
    final ecdhBytes = (await _ecdhKeyPair!.extract()).bytes;
    final signingBytes = (await _signingKeyPair!.extract()).bytes;

    final ecdhSecretBox = await _keyEncryptionCipher.encrypt(ecdhBytes, secretKey: kek);
    final signingSecretBox = await _keyEncryptionCipher.encrypt(signingBytes, secretKey: kek);

    // 4. Сохраняем зашифрованные данные и соль
    await _storage.write(key: PBKDF2_SALT_PREFIX + _userAlias!, value: base64.encode(saltList));
    // Используем JSON-хелперы для хранения SecretBox
    await _storage.write(key: ecdhKeyAlias, value: _encodeSecretBox(ecdhSecretBox));
    await _storage.write(key: signingKeyAlias, value: _encodeSecretBox(signingSecretBox));

    // 5. Сохраняем хеш пароля для проверки входа (BCrypt)
    final passHash = BCrypt.hashpw(password, BCrypt.gensalt());
    await _storage.write(key: PASS_HASH_PREFIX + _userAlias!, value: passHash);

    debugPrint('🔑 Ключи ${_userAlias!} зашифрованы и сохранены.');
  }

  /// Восстанавливает и расшифровывает ключи E2EE из хранилища
  Future<void> _decryptAndRestoreKeys(String password, String ecdhKeyAlias, String signingKeyAlias) async {
    // 1. Загружаем Salt
    final saltBase64 = await _storage.read(key: PBKDF2_SALT_PREFIX + _userAlias!);
    if (saltBase64 == null) throw Exception('Нет данных о регистрации. Пожалуйста, зарегистрируйтесь.');
    final salt = base64.decode(saltBase64);

    // 2. Получаем KEK из введенного пароля и соли
    final kek = await _deriveKeyFromPassword(password, salt);

    // 3. Загружаем зашифрованные ключи и проверяем на null
    final ecdhEncoded = await _storage.read(key: ecdhKeyAlias);
    final signingEncoded = await _storage.read(key: signingKeyAlias);

    if (ecdhEncoded == null || signingEncoded == null) {
      throw Exception('Encrypted key data is missing. Please re-register or check storage.');
    }

    // 4. Декодируем SecretBox из JSON (используем JSON-хелперы)
    final ecdhSecretBox = _decodeSecretBox(ecdhEncoded);
    final signingSecretBox = _decodeSecretBox(signingEncoded);

    try {
      // 5. Расшифровываем ключи (с проверкой MAC)
      final ecdhBytes = await _keyEncryptionCipher.decrypt(ecdhSecretBox, secretKey: kek);
      final signingBytes = await _keyEncryptionCipher.decrypt(signingSecretBox, secretKey: kek);

      // 6. Восстанавливаем KeyPair
      _ecdhKeyPair = await _x25519.newKeyPairFromSeed(ecdhBytes);
      // Приватный ключ Ed25519 - это 32 байта seed
      _signingKeyPair = await _ecdsa.newKeyPairFromSeed(signingBytes);
      signingPublicKey = await _signingKeyPair!.extractPublicKey();

      debugPrint('✅ Ключи ${_userAlias!} загружены и дешифрованы.');

    } catch (e) {
      // Ошибка дешифрования означает неверный пароль или повреждение данных
      throw Exception('Ошибка дешифрования. Неверный пароль или повреждение данных. Проверьте пароль! ${e.toString()}');
    }
  }

  /// Главный метод входа/регистрации
  Future<PublicKey> initializeOrLoginUser(String password, String ecdhKeyAlias, String signingKeyAlias) async {
    _userAlias = ecdhKeyAlias.split('Ecdh').first; // Используем 'Alice' или 'Bob' из 'AliceEcdh'

    // Проверяем наличие хеша пароля, чтобы определить, зарегистрирован ли пользователь
    final storedHash = await _storage.read(key: PASS_HASH_PREFIX + _userAlias!);
    final isRegistered = storedHash != null;

    if (isRegistered) {
      // --- ЛОГИН ---
      if (!BCrypt.checkpw(password, storedHash!)) {
        throw Exception('Неверный пароль.');
      }

      await _decryptAndRestoreKeys(password, ecdhKeyAlias, signingKeyAlias);

    } else {
      // --- ПЕРВАЯ РЕГИСТРАЦИЯ ---

      _ecdhKeyPair = await _x25519.newKeyPair();
      _signingKeyPair = await _ecdsa.newKeyPair();
      signingPublicKey = await _signingKeyPair!.extractPublicKey();

      await _encryptAndStoreKeys(password, ecdhKeyAlias, signingKeyAlias);
    }

    return await _ecdhKeyPair!.extractPublicKey();
  }

  /// Смена пароля: повторное шифрование ключей с новым паролем
  Future<void> changePassword(String newPassword, String ecdhKeyAlias, String signingKeyAlias) async {
    if (_ecdhKeyPair == null) {
      throw Exception("Ключи должны быть сначала расшифрованы (попробуйте войти с текущим паролем).");
    }

    await _encryptAndStoreKeys(newPassword, ecdhKeyAlias, signingKeyAlias);
  }

  /// Сброс локального состояния ключей
  void resetKeys() {
    _ecdhKeyPair = null;
    _signingKeyPair = null;
    sharedSecret = null;
    remoteECDHPublicKey = null;
    signingPublicKey = null;
    _userAlias = null;
    debugPrint('🔑 Локальные ключи сброшены из памяти.');
  }

  // --- МЕТОДЫ E2EE ---

  Future<void> setupChat(
      String ecdhKeyAlias, String signingKeyAlias, PublicKey recipientECDHPublicKey) async {
    if (_ecdhKeyPair == null) throw Exception('ECDH приватный ключ не инициализирован!');

    remoteECDHPublicKey = recipientECDHPublicKey;

    sharedSecret = await _x25519.sharedSecretKey(
      keyPair: _ecdhKeyPair!,
      remotePublicKey: remoteECDHPublicKey!,
    );
    debugPrint('🤝 Общий секрет установлен для ${_userAlias!}');
  }

  Future<EncryptedMessage> encryptAndSign(String plaintext) async {
    if (sharedSecret == null || _signingKeyPair == null) {
      throw Exception('Чат или ключ подписи не инициализированы!');
    }

    final messageBytes = utf8.encode(plaintext);
    final nonce = _aesGcm.newNonce();

    // 1. Шифрование (AES-GCM)
    final secretBox = await _aesGcm.encrypt(
      messageBytes,
      secretKey: sharedSecret!,
      nonce: nonce,
    );

    // 2. Подпись (Ed25519)
    final signature = await _ecdsa.sign(
      // Подписываем только зашифрованный текст. MAC является частью SecretBox
      secretBox.cipherText,
      keyPair: _signingKeyPair!,
    );

    return EncryptedMessage(
      ciphertext: secretBox.cipherText,
      nonce: nonce,
      mac: secretBox.mac.bytes,
      signature: signature.bytes,
    );
  }

  Future<String> decryptAndVerify(EncryptedMessage encryptedMessage, PublicKey senderSigningPublicKey) async {
    if (sharedSecret == null) throw Exception('Чат не инициализирован!');

    // 1. Проверка подписи (используем публичный ключ Ed25519 собеседника)
    final isValid = await _ecdsa.verify(
      encryptedMessage.ciphertext,
      signature: Signature(encryptedMessage.signature, publicKey: senderSigningPublicKey),
    );

    if (!isValid) throw Exception('Проверка подписи не удалась!');

    // создание SecretBox
    final secretBox = SecretBox(
      encryptedMessage.ciphertext,
      nonce: encryptedMessage.nonce,
      mac: Mac(encryptedMessage.mac),
    );

    // 2. Дешифрование
    final decryptedBytes = await _aesGcm.decrypt(
      secretBox,
      secretKey: sharedSecret!,
    );

    return utf8.decode(decryptedBytes);
  }
}

class EncryptedMessage {
  final List<int> ciphertext;
  final List<int> nonce;
  final List<int> mac;
  final List<int> signature;

  EncryptedMessage({
    required this.ciphertext,
    required this.nonce,
    required this.mac,
    required this.signature,
  });
}