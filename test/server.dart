import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:proton_session/src/srp/pmhash.dart';
import 'package:proton_session/src/srp/util.dart';

class TestServer {
  late final BigInt _modulus;
  final BigInt _verifier;
  bool _authenticated = false;
  final Hash hash;
  final List<int> user;

  late final BigInt _b;
  late final BigInt _B;
  late BigInt _secret;
  late BigInt _A;

  TestServer(this.user, Uint8List nBin, this._verifier,
      {this.hash = const PMHash()}) {
    _b = getRandomOfLength(32);
    _modulus = nBin.readBytes();
    _B = (_calculateK() * _verifier + BigInt.from(2).modPow(_b, _modulus))
        .remainder(_modulus);
  }

  Uint8List get challenege => _B.writeBigInt();
  Uint8List get sessionKey => _secret.writeBigInt();
  bool get authenticated => _authenticated;

  BigInt _calculateK() {
    return Uint8List.fromList(hash
            .convert(BigInt.from(2).writeBigInt() + _modulus.writeBigInt())
            .bytes)
        .readBytes();
  }

  Digest _calculateProof(Uint8List B) {
    return hash.convert(_A.writeBigInt() + B + _secret.writeBigInt());
  }

  Digest processChallenge(Uint8List clientChallenge, Uint8List clientProof,
      {int version = pmVersion}) {
    _A = clientChallenge.readBytes();

    final BigInt u = Uint8List.fromList(
            hash.convert(_A.writeBigInt() + _B.writeBigInt()).bytes)
        .readBytes();

    _secret = (_A * _verifier.modPow(u, _modulus)).modPow(_b, _modulus);

    if (Digest(clientProof) != _calculateProof(_B.writeBigInt())) {
      throw StateError('Incorrect');
    }
    _authenticated = true;
    return _calculateProof(clientProof);
  }
}
