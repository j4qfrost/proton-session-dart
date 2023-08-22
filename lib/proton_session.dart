import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';

import 'src/constants.dart';
import 'src/srp/user.dart';
import 'src/srp/pyuser.dart';
import 'src/errors.dart';

import 'package:dart_pg/dart_pg.dart';

class ProtonSession {
  final String apiUrl;
  final String appVersion;
  final String? clientSecret;
  late final HttpClient _client;
  final Map<String, String> _headers = {
    'Accept': 'application/vnd.protonmail.v1+json',
  };

  final Map<String, String> _cookies = {};

  final Map<String, dynamic> _sessionData = {};
  String? _captchaToken;

  String? get uid => _sessionData['UID'];
  String? get accessToken => _sessionData['AccessToken'];
  String? get refreshToken => _sessionData['RefreshToken'];
  String? get passwordMode => _sessionData['PasswordMode'];
  String? get scope => _sessionData['Scope'];

  String get captchaUrl =>
      '$apiUrl/core/v4/captcha${(_captchaToken != null) ? "?Token=$_captchaToken" : ""}';

  ProtonSession(
    this.apiUrl, {
    this.appVersion = '3',
    String? userAgent,
    this.clientSecret,
    Map<String, String> proxies = const {},
  }) {
    _client = HttpClient();
    _client.userAgent = userAgent;
    _client.findProxy = (proxies.isNotEmpty)
        ? (url) {
            return 'PROXY ${proxies[url.authority]}';
          }
        : null;
    _client.connectionTimeout = Duration(seconds: defaultTimeout.$1);
    _client.idleTimeout = Duration(seconds: defaultTimeout.$2);
    _headers['x-pm-appversion'] = 'web-account@5.0.47.7';
    if (userAgent != null) _headers['User-Agent'] = userAgent;
  }

  Future<dynamic> apiRequest(
    String method,
    String path, {
    String? host,
    Map<String, dynamic>? queryParameters,
    Object? body,
  }) async {
    final Uri uri = Uri(
        scheme: 'https',
        host: host ?? apiUrl,
        path: path,
        queryParameters: queryParameters);
    final HttpClientRequest req = await _client.openUrl(method, uri);
    for (MapEntry<String, String> header in _headers.entries) {
      req.headers.set(header.key, header.value);
    }

    req.headers.set(
        'Cookie', _cookies.entries.map((e) => '${e.key}=${e.value}').join(';'));

    if (body != null) {
      if (const ['GET', 'HEAD', 'DELETE'].contains(method)) {
        throw StateError('$method does not allow sending body!');
      }
      final String jsonBody = jsonEncode(body);
      req.headers.contentType = ContentType.json;
      req.headers.contentLength = jsonBody.length;
      req.write(jsonBody);
    }
    final HttpClientResponse res = await req.close();
    final String responseBody = await res.transform(Utf8Decoder()).join();

    _storeCookies(res.headers);

    try {
      final jsonData = json.decode(responseBody);
      if (!const [1000, 1001].contains(jsonData['Code'])) {
        _captchaToken = jsonData['Details']['HumanVerificationToken'];
        jsonData['Headers'] = res.headers.toString();
        throw ProtonAPIError(uri, jsonData);
      }
      return jsonData;
    } on FormatException {
      if (res.statusCode != 200) {
        throw ProtonAPIError(uri, {
          'Code': res.statusCode,
          'Error': res.reasonPhrase,
          'Headers': res.headers.toString(),
        });
      }
    } on TypeError {
      if (res.statusCode != 200) {
        rethrow;
      }
    }
  }

  void _storeCookies(HttpHeaders headers) {
    headers.forEach((String key, List<String> cookies) {
      if (key.toLowerCase() == 'set-cookie') {
        for (String h in cookies) {
          final List<String> splitHeaders = h.split('; ');
          for (String cookie in splitHeaders) {
            final List<String> parts = cookie.split('=');
            _cookies[parts.first] = parts.skip(1).join();
          }
        }
      }
    });
  }

  Future<Uint8List> verifyModulus(String text) async {
    final SignedMessage message = await OpenPGP.readSignedMessage(text);
    final SignedMessage verified =
        await message.verify([await OpenPGP.readPublicKey(srpModulusKey)]);
    if (!verified.verifications.first.verified &&
        message.text == srpModulusKeyFingerprint) {
      throw StateError('Invalid modulus');
    }
    return Uint8List.fromList(base64Decode(message.text));
  }

  Future<void> logout() async {
    if (_sessionData.isNotEmpty) {
      await apiRequest('DELETE', '/auth').then((resp) {
        _headers.remove('Authorization');
        _headers.remove('x-pm-uid');
        _sessionData.clear();
      });
    }
  }

  Future<String> authenticate(String username, String password) async {
    await logout();
    final Map<String, Object> payload = {
      'Username': username,
      if (clientSecret != null) 'ClientSecret': clientSecret!,
    };

    final sessionsResponse = await apiRequest(
      'POST',
      '/api/auth/v4/sessions',
    );

    _headers['Authorization'] = 'Bearer ${sessionsResponse["AccessToken"]}';
    _headers['x-pm-uid'] = sessionsResponse['UID'];

    await apiRequest('POST', '/api/core/v4/auth/cookies', body: {
      'UID': sessionsResponse['UID'],
      'ResponseType': 'token',
      'GrantType': 'refresh_token',
      'RefreshToken': sessionsResponse['RefreshToken'],
      'RedirectURI': 'https://protonmail.com',
      'Persistent': 0,
    });

    final infoResponse = await apiRequest('POST', '/api/core/v4/auth/info',
        host: 'account.proton.me', body: payload);

    final Uint8List modulus = await verifyModulus(infoResponse['Modulus']);

    final Uint8List serverChallenge =
        base64Decode(infoResponse['ServerEphemeral']);
    final Uint8List salt = base64Decode(infoResponse['Salt']);

    final User usr = PyUser(password, modulus);
    final Digest clientProof = usr.processChallenge(salt, serverChallenge);
    payload.addAll({
      'ClientEphemeral': base64Encode(usr.challenge),
      'ClientProof': base64Encode(clientProof.bytes),
      'SRPSession': infoResponse['SRPSession'],
    });
    final authResponse = await apiRequest('POST', '/api/core/v4/auth',
        host: 'account.proton.me', body: payload);

    if (authResponse['ServerProof'] == null) {
      throw StateError('Invalid Password');
    }

    if (!usr.verifySession(Digest(base64Decode(authResponse['ServerProof'])))) {
      throw StateError('Invalid server proof');
    }

    _sessionData['UID'] = authResponse['UID'];
    _sessionData['AccessToken'] = authResponse['AccessToken'];
    _sessionData['RefreshToken'] = authResponse['RefreshToken'];
    _sessionData['PasswordMode'] = authResponse['PasswordMode'];

    if (_sessionData['UID'] != null) {
      _headers['x-pm-uid'] = _sessionData['UID'];
      _headers['Authorization'] = 'Bearer ${_sessionData["AccessToken"]}';
    }
    return _sessionData['Scope'] = authResponse['Scope'];
  }

  Future<String> provide2fa(String code) async {
    final res = await apiRequest('POST', '/api/core/v4/auth/2fa',
        body: {'TwoFactorCode': code});
    return _sessionData["Scope"] = res["Scope"];
  }

  Future<dynamic> refresh() async {
    return apiRequest('POST', '/auth/refresh', body: {
      'ResponseType': 'token',
      'GrantType': 'refresh_token',
      'RefreshToken': refreshToken,
      'RedirectURI': 'http://protonmail.ch',
    }).then((res) {
      _sessionData['AccessToken'] = res['AccessToken'];
      _sessionData['RefreshToken'] = res['RefreshToken'];
      _headers['Authorization'] = 'Bearer $accessToken';
    });
  }
}
