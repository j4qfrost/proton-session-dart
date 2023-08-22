import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:proton_session/proton_session.dart';
import 'package:proton_session/src/srp/pyuser.dart';
import 'package:proton_session/src/srp/util.dart';
import 'package:test/test.dart';

import 'data.dart';
import 'server.dart';

void main() {
  tearDown(() {});
  test('Convert BigInt to/from Uint8List', () {
    final List<int> original = '\x00abc\x00\x00'.codeUnits;
    final BigInt val = Uint8List.fromList(original).readBytes();
    final Uint8List bytes = val.writeBigInt(length: original.length);

    expect(bytes, original);
  }, skip: true);

  group('computeV', () {
    for (Map<String, Object?> instance in srpInstances) {
      final String username = instance['Username'] as String;
      test(username, () {
        final String password = instance['Password'] as String;
        final Uint8List nBin = Uint8List.fromList(
            BigInt.parse(instance["Modulus"] as String, radix: 16)
                .writeBigInt()
                .reversed
                .toList());
        final String salt = instance["Salt"] as String;
        final Type? errorType = instance['Exception'] as Type?;
        if (errorType != null) {
          try {
            final PyUser user = PyUser(password, nBin);
            user.computeV(bytesS: base64Decode(salt));
          } catch (e) {
            if (e.runtimeType != errorType) {
              rethrow;
            }
          }
        } else {
          final PyUser user = PyUser(password, nBin);
          final (Uint8List, Uint8List) result =
              user.computeV(bytesS: base64Decode(salt));
          expect(base64Encode(result.$1), salt,
              reason: 'Wrong salt while generating v, $username');
          expect(base64Encode(result.$2), instance['Verifier'],
              reason: 'Wrong verifier while generating v, $username');
        }
      });
    }
  }, skip: true);

  group('generateV', () {
    for (Map<String, Object?> instance in srpInstances) {
      final Type? errorType = instance['Exception'] as Type?;
      if (errorType != null) {
        continue;
      }

      final String username = instance['Username'] as String;
      test(username, () {
        final String password = instance['Password'] as String;
        final Uint8List nBin = Uint8List.fromList(
            BigInt.parse(instance["Modulus"] as String, radix: 16)
                .writeBigInt()
                .reversed
                .toList());
        final PyUser user = PyUser(password, nBin);
        final (Uint8List, Uint8List) expected = user.computeV();
        final (Uint8List, Uint8List) result =
            user.computeV(bytesS: expected.$1);
        expect(base64Encode(result.$1), base64Encode(expected.$1),
            reason: 'Wrong salt while generating v, $username');
        expect(base64Encode(result.$2), base64Encode(expected.$2),
            reason: 'Wrong verifier while generating v, $username');
      });
    }
  }, skip: true);
  group('SRP', () {
    for (Map<String, Object?> instance in srpInstances) {
      final Type? errorType = instance['Exception'] as Type?;
      if (errorType != null) {
        continue;
      }

      final String username = instance['Username'] as String;
      test(username, () {
        final String password = instance['Password'] as String;
        final BigInt modulus =
            BigInt.parse(instance['Modulus'] as String, radix: 16);
        final BigInt verifier =
            base64Decode(instance['Verifier'] as String).readBytes();
        final Uint8List nBin =
            Uint8List.fromList(modulus.writeBigInt().reversed.toList());
        final PyUser user = PyUser(password, nBin);
        final TestServer server =
            TestServer(username.codeUnits, nBin, verifier);

        final Uint8List clientProof = Uint8List.fromList(user
            .processChallenge(
                base64Decode(instance['Salt'] as String), server.challenege)
            .bytes);
        final Digest serverProof =
            server.processChallenge(user.challenge, clientProof);

        expect(user.verifySession(serverProof), isTrue);
        expect(user.sessionKey, server.sessionKey);
        expect(server.authenticated, isTrue);
      });
    }
  }, skip: true);

  group('verifyModulus', () {
    final ProtonSession session = ProtonSession('dummy');
    for ((int, Map<String, Object?>) pair in modulusInstances.indexed) {
      final String modulus = pair.$2['SignedModulus'] as String;
      test('entry ${pair.$1}', () async {
        final Type? errorType = pair.$2['Exception'] as Type?;
        if (errorType != null) {
          try {
            await session.verifyModulus(modulus);
          } catch (e) {
            expect(e.runtimeType, errorType);
          }
        } else {
          final Uint8List verified = await session.verifyModulus(modulus);

          expect(verified.readBytes(),
              base64Decode(pair.$2['Decoded'] as String).readBytes());
        }
      });
    }
  });
}
