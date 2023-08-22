import 'dart:convert';

import 'package:crypto/crypto.dart';

class PMHash extends Hash {
  const PMHash();

  @override
  int get blockSize => 256;

  @override
  Digest convert(List<int> input) {
    final List<int> digest0 = sha512.convert(input + [0]).bytes;
    final List<int> digest1 = sha512.convert(input + [1]).bytes;
    final List<int> digest2 = sha512.convert(input + [2]).bytes;
    final List<int> digest3 = sha512.convert(input + [3]).bytes;

    return Digest(<int>[...digest0, ...digest1, ...digest2, ...digest3]);
  }

  @override
  ByteConversionSink startChunkedConversion(Sink<Digest> sink) {
    throw UnsupportedError(
        "This converter does not support chunked conversions: $this");
  }
}
