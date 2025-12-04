// lib/secure_chat_service.dart
import 'dart:convert';
import 'package:cryptography/cryptography.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

const ALICE_PRIV_KEY = 'alice_priv';
const BOB_PRIV_KEY = 'bob_priv';

class SecureChatService {
  final _storage = const FlutterSecureStorage();
  final _ecdsa = Ed25519();
  final _aesGcm = AesGcm.withGcm(
      keyLength: 32,
      macAlgorithm: Hmac.sha256()); // AES-256 для сообщений

  SimpleKeyPair? localKeyPair;
  PublicKey? remotePublicKey;
  SecretKey? sharedSecret;

  // 1. АУТЕНТИФИКАЦИЯ И УПРАВЛЕНИЕ КЛЮЧАМИ (Secure Key Management)
  // ---

  // Симуляция регистрации: генерируем и сохраняем ключи
  Future<SimpleKeyPair> initializeUser(String keyAlias) async {
    final newKeyPair = await _ecdsa.newKeyPair();
    final privateKeyBytes = (await newKeyPair.extractPrivateKey()).bytes;

    // Сохранение приватного ключа в Secure Storage
    await _storage.write(
      key: keyAlias,
      value: base64.encode(privateKeyBytes),
    );
    localKeyPair = newKeyPair;
    return newKeyPair;
  }

  // 2. ОБМЕН КЛЮЧАМИ (ECDH Key Exchange)
  // ---

  Future<void> setupChat(
      String localKeyAlias, PublicKey recipientPublicKey) async {
    // 1. Загрузка локального приватного ключа
    final privateKeyBase64 = await _storage.read(key: localKeyAlias);
    if (privateKeyBase64 == null) {
      throw Exception('Private key not found for $localKeyAlias');
    }

    final privateKeyBytes = base64.decode(privateKeyBase64);

    // Восстановление SimpleKeyPair (для ECDH и подписей)
    // Важно: для ECDH используется X25519, но ключ Ed25519 конвертируем
    final x25519 = X25519();
    localKeyPair = SimpleKeyPair(
      privateKey: SimplePrivateKey(privateKeyBytes, algorithm: x25519),
      publicKey: recipientPublicKey,
    );
    remotePublicKey = recipientPublicKey;

    // 2. ВЫЧИСЛЕНИЕ ОБЩЕГО СЕКРЕТА
    sharedSecret = await x25519.sharedSecret(
      localKeyPair: localKeyPair!,
      remotePublicKey: remotePublicKey!,
    );
  }

  // 3. ШИФРОВАНИЕ И ПОДПИСЬ СООБЩЕНИЯ (AES-256 & Digital Signatures)
  // ---

  Future<EncryptedMessage> encryptAndSign(String plaintext) async {
    final messageBytes = utf8.encode(plaintext);

    // 1. Шифрование сообщения (AES-256 GCM)
    final nonce = _aesGcm.newNonce();
    final secretBox = await _aesGcm.encrypt(
      messageBytes,
      secretKey: sharedSecret!,
      nonce: nonce,
    );

    // 2. Подпись сообщения (ЦИФРОВАЯ ПОДПИСЬ)
    final signingKeyPair = SimpleKeyPair(
        privateKey: (await localKeyPair!.extractPrivateKey()),
        publicKey: (await localKeyPair!.extractPublicKey()),
        algorithm: _ecdsa // Используем Ed25519 для подписи
    );

    // Подписываем именно зашифрованный текст для проверки целостности
    final signature = await _ecdsa.sign(
      secretBox.cipherText,
      keyPair: signingKeyPair,
    );

    return EncryptedMessage(
      ciphertext: secretBox.cipherText,
      nonce: nonce,
      mac: secretBox.mac.bytes,
      signature: signature.bytes,
    );
  }

  // 4. ПРОВЕРКА ЦЕЛОСТНОСТИ И ДЕШИФРОВАНИЕ
  // ---

  Future<String> decryptAndVerify(EncryptedMessage encryptedMessage,
      PublicKey senderPublicKey) async {
    final secretBox = SecretBox(
      encryptedMessage.ciphertext,
      nonce: encryptedMessage.nonce,
      mac: Mac(encryptedMessage.mac),
    );

    // 1. ПРОВЕРКА ЦЕЛОСТНОСТИ и АУТЕНТИЧНОСТИ (Цифровая Подпись)
    final isSignatureValid = await _ecdsa.verify(
      encryptedMessage.ciphertext, // Проверяем подпись зашифрованного текста
      signature: Signature(encryptedMessage.signature, publicKey: senderPublicKey),
    );

    if (!isSignatureValid) {
      throw Exception('Signature verification failed! Message integrity compromised.');
    }

    // 2. ДЕШИФРОВАНИЕ (AES-256 GCM)
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