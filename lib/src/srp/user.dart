// # N    A large safe prime (N = 2q+1, where q is prime)
// #      All arithmetic is done modulo N.
// # g    A generator modulo N
// # k    Multiplier parameter (k = H(N, g) in SRP-6a, k = 3 for legacy SRP-6)
// # s    User's salt
// # I    Username
// # p    Cleartext Password
// # H()  One-way hash function
// # ^    (Modular) Exponentiation
// # u    Random scrambling parameter
// # a,b  Secret ephemeral values
// # A,B  Public ephemeral values
// # x    Private key (derived from p and s)
// # v    Password verifier
import 'dart:typed_data';

import 'package:crypto/crypto.dart';

abstract interface class User {
  bool get authenticated;

  Uint8List get ephemeralSecret;

  Uint8List? get sessionKey;

  Uint8List get challenge;

  bool verifySession(Digest serverProof);

  (Uint8List, Uint8List) computeV({Uint8List? bytesS});

  Digest processChallenge(Uint8List bytesS, Uint8List bytesServerChallenge);
}
