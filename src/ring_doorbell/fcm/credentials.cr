module RingDoorbell::FCM
  # The push-receiver identity created by `FCM::Registration` and persisted in
  # the client's token file. Binary values are stored URL-safe base64 encoded
  # (no padding), matching the encoding sent to the FCM registration API.
  struct Credentials
    include JSON::Serializable

    # Device identity from GCM check-in (decimal strings — used verbatim in
    # the `AidLogin` header and the MCS login request).
    property android_id : String
    property security_token : String

    # GCM registration token (becomes the FCM endpoint path).
    property gcm_token : String

    # The token Ring pushes notifications to.
    property fcm_token : String

    # WebPush encryption keys: P-256 keypair + 16-byte auth secret.
    property private_key : String
    property public_key : String
    property auth_secret : String

    def initialize(@android_id, @security_token, @gcm_token, @fcm_token,
                   @private_key, @public_key, @auth_secret)
    end

    # Encode bytes the way every Google push API expects them.
    def self.encode(bytes : Bytes) : String
      Base64.urlsafe_encode(bytes, padding: false)
    end

    # Decode URL-safe base64, tolerating missing padding.
    def self.decode(value : String) : Bytes
      padded = value + "=" * ((4 - value.size % 4) % 4)
      Base64.decode(padded)
    end

    # The P-256 private key used to decrypt push payloads.
    def ec_private_key : OpenSSL::PKey::EC
      OpenSSL::PKey::EC.from_private_bytes(Credentials.decode(private_key), "P-256")
    end

    # Our uncompressed (65 byte) public key — the `p256dh` registration value.
    def public_key_bytes : Bytes
      Credentials.decode(public_key)
    end

    def auth_secret_bytes : Bytes
      Credentials.decode(auth_secret)
    end
  end
end
