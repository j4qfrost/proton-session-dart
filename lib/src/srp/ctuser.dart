import 'dart:typed_data';

import 'package:crypto/crypto.dart';

import 'user.dart';

class CtUser implements User {
  @override
  // TODO: implement authenticated
  bool get authenticated => throw UnimplementedError();

  @override
  // TODO: implement challenge
  Uint8List get challenge => throw UnimplementedError();

  @override
  (Uint8List, Uint8List) computeV({Uint8List? bytesS}) {
    // TODO: implement computeV
    throw UnimplementedError();
  }

  @override
  // TODO: implement ephemeralSecret
  Uint8List get ephemeralSecret => throw UnimplementedError();

  @override
  Digest processChallenge(Uint8List bytesS, Uint8List bytesServerChallenge) {
    // TODO: implement processChallenge
    throw UnimplementedError();
  }

  @override
  // TODO: implement sessionKey
  Uint8List? get sessionKey => throw UnimplementedError();

  @override
  bool verifySession(Digest serverProof) {
    // TODO: implement verifySession
    throw UnimplementedError();
  }
}
