const String ALICE_ECDH_KEY = 'AliceEcdh';
const String BOB_ECDH_KEY = 'BobEcdh';
const String ALICE_SIGN_KEY = 'AliceSign';
const String BOB_SIGN_KEY = 'BobSign';

enum User { Alice, Bob }

class MessageStorage {
  static List<Map<String, String>> messages = [];
}