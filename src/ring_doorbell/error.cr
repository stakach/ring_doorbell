module RingDoorbell
  # Base class for every error raised by this library.
  class Error < Exception
  end

  # Raised when authentication with Ring fails (bad credentials, expired or
  # revoked refresh token, invalid 2FA code).
  class AuthError < Error
  end

  # Raised when Ring requires a two-factor code to complete a password login.
  # Prompt the user for the code (sent via `tsv_state`: "sms" / "email" /
  # "totp") and retry the login passing it along.
  class TwoFactorRequired < AuthError
    getter phone : String?
    getter tsv_state : String?

    def initialize(message = "two-factor authentication code required",
                   @phone = nil, @tsv_state = nil)
      super(message)
    end
  end

  # Raised when a server returns an unexpected status code or a payload that
  # cannot be parsed.
  class ResponseError < Error
  end

  # Raised when a connection cannot be established or is lost.
  class ConnectionError < Error
  end

  # Raised when a request or handshake does not complete within the
  # configured timeout.
  class TimeoutError < Error
  end

  # Raised when an encrypted push payload fails to decrypt. These are
  # expected occasionally (non-Ring pushes, key rotation) and are handled
  # internally by skipping the message.
  class DecryptError < Error
  end

  # Raised when a protocol frame or message is malformed.
  class ProtocolError < Error
  end
end
