abstract class ProtonError extends Error {
  late final String message;
  ProtonError(this.message);
}

class NetworkError extends ProtonError {
  NetworkError(super.message);
}

class TLSPinningError extends ProtonError {
  TLSPinningError(super.message);
}

class NewConnectionError extends ProtonError {
  NewConnectionError(super.message);
}

class ConnectionTimeOutError extends ProtonError {
  ConnectionTimeOutError(super.message);
}

class UnknownConnectionError extends ProtonError {
  UnknownConnectionError(super.message);
}

class MissingDepedencyError extends ProtonError {
  MissingDepedencyError(super.message);
}

class ProtonAPIError extends ProtonError {
  late final int code;
  late final String headers;
  late final dynamic details;
  final Uri uri;
  ProtonAPIError(this.uri, Map<String, Object?> ret)
      : super(ret['Error'] as String? ?? 'N/A') {
    code = ret['Code'] as int;
    headers = ret['Headers'] as String? ?? 'N/A';
    details = ret['Details'];
  }
}
