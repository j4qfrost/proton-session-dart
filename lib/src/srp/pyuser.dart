// ignore_for_file: non_constant_identifier_names

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'pmhash.dart';

import 'user.dart';
import 'util.dart';

class PyUser implements User {
  final Hash hash;
  bool _authenticated = false;
  late Uint8List _K;
  late final BigInt _N;
  late final BigInt _g;
  late final BigInt _k;
  late final List<int> _p;
  late final BigInt _a;
  late final BigInt _A;
  late Uint8List _M;
  late Uint8List _bytesS;

  PyUser(String password, Uint8List nBin,
      {List<int> gHex = const [0x32],
      Uint8List? bytesa,
      Uint8List? bytesA,
      this.hash = const PMHash()}) {
    if (bytesa != null && bytesa.length != 32) {
      throw StateError('32 bytes required for bytesa');
    }

    if (password.isEmpty) {
      throw StateError('Invalid password');
    }

    _N = nBin.readBytes();
    _g = BigInt.parse(String.fromCharCodes(gHex), radix: 16);
    _k = _hashk();
    _p = utf8.encode(password);

    if (bytesa != null) {
      _a = bytesa.readBytes();
    } else {
      _a = getRandomOfLength(32);
    }

    if (bytesA != null) {
      _A = bytesA.readBytes();
    } else {
      _A = _g.modPow(_a, _N);
    }
  }

  @override
  bool get authenticated => _authenticated;

  @override
  Uint8List get ephemeralSecret => _a.writeBigInt();

  @override
  Uint8List get challenge => _A.writeBigInt();

  @override
  Uint8List? get sessionKey => (_authenticated) ? _K : null;

  @override
  bool verifySession(Digest serverProof) {
    if (!_authenticated) {
      try {
        _authenticated = _calculateProof(_M) == serverProof;
      } catch (_) {
        return false;
      }
    }
    return _authenticated;
  }

  @override
  (Uint8List, Uint8List) computeV({Uint8List? bytesS}) {
    _bytesS = bytesS ??
        getRandomOfLength(saltLenBytes).writeBigInt(length: saltLenBytes);
    final BigInt x = _calculateX();
    return (_bytesS, _g.modPow(x, _N).writeBigInt(length: srpLenBytes));
  }

  @override
  Digest processChallenge(Uint8List bytesS, Uint8List bytesServerChallenge) {
    _bytesS = bytesS;
    final BigInt b = bytesServerChallenge.readBytes();

    if (b.remainder(_N) == BigInt.zero) {
      throw StateError('Invalid challenge');
    }

    final BigInt u = Uint8List.fromList(
            hash.convert(_A.writeBigInt() + b.writeBigInt()).bytes)
        .readBytes();

    if (u == BigInt.zero) {
      throw StateError('Invalid challenge');
    }

    final BigInt x = _calculateX();
    final BigInt v = _g.modPow(x, _N);

    final BigInt S = (b - _k * v).modPow(_a + u * x, _N);
    _K = S.writeBigInt();
    final Digest digest = _calculateProof(b.writeBigInt());
    _M = Uint8List.fromList(digest.bytes);
    return digest;
  }

  BigInt _hashk() {
    return Uint8List.fromList(
            hash.convert(_g.writeBigInt() + _N.writeBigInt()).bytes)
        .readBytes();
  }

  BigInt _calculateX() {
    final Digest exp =
        hashPassword(hash, String.fromCharCodes(_p), _bytesS, _N.writeBigInt());
    return Uint8List.fromList(exp.bytes).readBytes();
  }

  Digest _calculateProof(Uint8List B) {
    return hash.convert(_A.writeBigInt() + B + _K);
  }
}
