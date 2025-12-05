import 'dart:convert';
import 'package:cryptography/cryptography.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

// ⚠️ КОНСТАНТЫ: Отдельно для ECDH и Подписи
const ALICE_ECDH_KEY = 'alice_ecdh';
const BOB_ECDH_KEY = 'bob_ecdh';
const ALICE_SIGN_KEY = 'alice_sign';
const BOB_SIGN_KEY = 'bob_sign';

class SecureChatService {
  final _storage = const FlutterSecureStorage();
  final _x25519 = X25519();
  final _ecdsa = Ed25519();
  final _aesGcm = AesGcm.with256bits();

  // ДВЕ ПАРЫ КЛЮЧЕЙ
  SimpleKeyPair? _ecdhKeyPair; // X25519 для обмена ключами
  SimpleKeyPair? _signingKeyPair; // Ed25519 для подписи

  PublicKey? remoteECDHPublicKey; // Публичный ключ собеседника для ECDH
  PublicKey? signingPublicKey; // Публичный ключ пользователя для подписи
  SecretKey? sharedSecret;

  /// Генерация и сохранение ключей пользователя (ECDH и Ed25519)
  Future<PublicKey> initializeUser(String ecdhKeyAlias, String signingKeyAlias) async {
    // 1. ECDH Key (X25519) - для обмена ключами
    final ecdhPair = await _x25519.newKeyPair();
    final ecdhKeyData = await ecdhPair.extract();
    await _storage.write(key: ecdhKeyAlias, value: base64.encode(ecdhKeyData.bytes));

    // 2. Signing Key (Ed25519) - для подписи
    final signingPair = await _ecdsa.newKeyPair();
    final signingKeyData = await signingPair.extract();
    await _storage.write(key: signingKeyAlias, value: base64.encode(signingKeyData.bytes));

    _ecdhKeyPair = ecdhPair;
    _signingKeyPair = signingPair;

    signingPublicKey = await signingPair.extractPublicKey();
    return await ecdhPair.extractPublicKey();
  }

  /// Настройка чата с получением общего секрета
  Future<void> setupChat(
      String ecdhKeyAlias, String signingKeyAlias, PublicKey recipientECDHPublicKey) async {
    // 1. Восстановление ECDH ключа
    final ecdhKeyBase64 = await _storage.read(key: ecdhKeyAlias);
    if (ecdhKeyBase64 == null) throw Exception('ECDH private key not found!');
    final ecdhPrivateKeyBytes = base64.decode(ecdhKeyBase64);
    _ecdhKeyPair = await _x25519.newKeyPairFromSeed(ecdhPrivateKeyBytes);
    remoteECDHPublicKey = recipientECDHPublicKey;

    // 2. Восстановление ключа подписи
    final signingKeyBase64 = await _storage.read(key: signingKeyAlias);
    if (signingKeyBase64 == null) throw Exception('Signing private key not found!');
    final signingPrivateKeyBytes = base64.decode(signingKeyBase64);
    _signingKeyPair = await _ecdsa.newKeyPairFromSeed(signingPrivateKeyBytes);


    // 3. Вычисление общего секрета
    // ✅ ИСПРАВЛЕНИЕ: Используем 'keyPair' вместо 'privateKey'
    sharedSecret = await _x25519.sharedSecretKey(
      keyPair: _ecdhKeyPair!,
      remotePublicKey: remoteECDHPublicKey!,
    );
  }

  /// Шифрование и подпись сообщения (используем Ed25519 ключ)
  Future<EncryptedMessage> encryptAndSign(String plaintext) async {
    if (sharedSecret == null || _signingKeyPair == null) {
      throw Exception('Chat or Signing Key not initialized!');
    }

    final messageBytes = utf8.encode(plaintext);
    final nonce = _aesGcm.newNonce();

    // 1. Шифрование
    final secretBox = await _aesGcm.encrypt(
      messageBytes,
      secretKey: sharedSecret!,
      nonce: nonce,
    );

    // 2. Подпись (используем специальный ключ Ed25519)
    final signature = await _ecdsa.sign(
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

  /// Дешифрование и проверка подписи
  Future<String> decryptAndVerify(EncryptedMessage encryptedMessage, PublicKey senderSigningPublicKey) async {
    if (sharedSecret == null) throw Exception('Chat not initialized!');

    final secretBox = SecretBox(
      encryptedMessage.ciphertext,
      nonce: encryptedMessage.nonce,
      mac: Mac(encryptedMessage.mac),
    );

    // 1. Проверка подписи (используем публичный ключ Ed25519 собеседника)
    final isValid = await _ecdsa.verify(
      encryptedMessage.ciphertext,
      signature: Signature(encryptedMessage.signature, publicKey: senderSigningPublicKey),
    );

    if (!isValid) throw Exception('Signature verification failed!');

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