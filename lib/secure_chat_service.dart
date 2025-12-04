import 'dart:convert';
import 'package:cryptography/cryptography.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

// Имена ключей для симуляции двух пользователей
const ALICE_PRIV_KEY = 'alice_priv';
const BOB_PRIV_KEY = 'bob_priv';

class SecureChatService {
  final _storage = const FlutterSecureStorage();
  final _x25519 = X25519();
  final _ecdsa = Ed25519();
  final _aesGcm = AesGcm.with256bits();

  SimpleKeyPair? localKeyPair;
  PublicKey? remotePublicKey;
  SecretKey? sharedSecret;

  /// Генерация и сохранение ключа пользователя
  Future<SimpleKeyPair> initializeUser(String keyAlias) async {
    // Генерация X25519 пары
    final keyPair = await _x25519.newKeyPair();
    final keyData = await keyPair.extract();
    final privateKeyBytes = keyData.bytes;

    await _storage.write(
      key: keyAlias,
      value: base64.encode(privateKeyBytes),
    );

    localKeyPair = keyPair;
    return keyPair;
  }

  /// Настройка чата с получением общего секрета
  Future<void> setupChat(String localKeyAlias, PublicKey recipientPublicKey) async {
    final privateKeyBase64 = await _storage.read(key: localKeyAlias);
    if (privateKeyBase64 == null) {
      throw Exception('Private key not found for $localKeyAlias');
    }
    final privateKeyBytes = base64.decode(privateKeyBase64);

    // Восстановление пары из приватного ключа
    final keyPair = await _x25519.newKeyPairFromSeed(privateKeyBytes);
    localKeyPair = keyPair;
    remotePublicKey = recipientPublicKey;

    // Вычисление общего секрета
    sharedSecret = await _x25519.sharedSecretKey(
      keyPair: localKeyPair!,
      remotePublicKey: remotePublicKey!,
    );
  }

  /// Шифрование и подпись сообщения
  Future<EncryptedMessage> encryptAndSign(String plaintext) async {
    if (sharedSecret == null || localKeyPair == null) {
      throw Exception('Chat not initialized!');
    }

    final messageBytes = utf8.encode(plaintext);
    final nonce = _aesGcm.newNonce();

    final secretBox = await _aesGcm.encrypt(
      messageBytes,
      secretKey: sharedSecret!,
      nonce: nonce,
    );

    final signature = await _ecdsa.sign(
      secretBox.cipherText,
      keyPair: localKeyPair!,
    );

    return EncryptedMessage(
      ciphertext: secretBox.cipherText,
      nonce: nonce,
      mac: secretBox.mac.bytes,
      signature: signature.bytes,
    );
  }

  /// Дешифрование и проверка подписи
  Future<String> decryptAndVerify(EncryptedMessage encryptedMessage, PublicKey senderPublicKey) async {
    if (sharedSecret == null) throw Exception('Chat not initialized!');

    final secretBox = SecretBox(
      encryptedMessage.ciphertext,
      nonce: encryptedMessage.nonce,
      mac: Mac(encryptedMessage.mac),
    );

    final isValid = await _ecdsa.verify(
      encryptedMessage.ciphertext,
      signature: Signature(encryptedMessage.signature, publicKey: senderPublicKey),
    );

    if (!isValid) throw Exception('Signature verification failed!');

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
