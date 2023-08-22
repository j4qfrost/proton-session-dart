import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:bcrypt/bcrypt.dart';

import 'dart:math';

const int pmVersion = 4;
const int srpLenBytes = 256;
const int saltLenBytes = 10;

const String hashPrefix = '\$2y\$10\$';

// https://github.com/dart-lang/sdk/issues/32803#issuecomment-1228291047
extension ToList on BigInt {
  Uint8List writeBigInt({int length = srpLenBytes}) {
    BigInt number = this;
    final Uint8List result = Uint8List(length);
    final BigInt b256 = BigInt.from(256);
    for (int i = 0; i < length; i++) {
      result[i] = number.remainder(b256).toInt();
      number = number >> 8;
    }
    return result;
  }
}

extension ToBigInt on Uint8List {
  BigInt readBytes() {
    BigInt result = BigInt.zero;

    for (final int byte in reversed) {
      result = (result << 8) | BigInt.from(byte & 0xff);
    }
    return result;
  }
}

BigInt getRandom(int numBytes) {
  final Uint8List randomBytes = getRandomBytes(numBytes);
  return randomBytes.readBytes();
}

BigInt getRandomOfLength(int numBytes) {
  final offset = (numBytes * 8) - 1;
  final randomValue = getRandom(numBytes);
  return randomValue | (BigInt.one << offset);
}

Uint8List getRandomBytes(int numBytes) {
  final Random random = Random.secure();
  final List<int> randomBytes =
      List<int>.generate(numBytes, (_) => random.nextInt(256));
  return Uint8List.fromList(randomBytes);
}

Digest hashPassword(
    Hash hash, String password, List<int> salt, Uint8List modulus) {
  salt = List<int>.from((salt + 'proton'.codeUnits).sublist(0, 16));
  final String saltStr =
      BCrypt.encodeBase64(Int8List.fromList(salt), salt.length)
          .substring(0, 22);
  final String hashed = BCrypt.hashpw(password, hashPrefix + saltStr);
  return hash.convert(hashed.codeUnits + modulus);
}
