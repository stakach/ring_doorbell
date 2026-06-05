# The stdlib cipher wrapper does not expose AEAD tag control, needed for
# AES-128-GCM (WebPush payloads).
lib LibCrypto
  fun evp_cipher_ctx_ctrl = EVP_CIPHER_CTX_ctrl(ctx : EVP_CIPHER_CTX, type : Int32, arg : Int32, ptr : Void*) : Int32
end

class OpenSSL::Cipher
  EVP_CTRL_GCM_SET_TAG = 0x11
  EVP_CTRL_GCM_GET_TAG = 0x10

  # Provides the expected authentication tag before `#final` when decrypting
  # with an AEAD cipher; `#final` then fails if the data does not authenticate.
  def auth_tag=(tag : Bytes)
    raise Error.new("cipher is not authenticated") unless authenticated?
    if LibCrypto.evp_cipher_ctx_ctrl(@ctx, EVP_CTRL_GCM_SET_TAG, tag.size, tag.to_unsafe.as(Void*)) != 1
      raise Error.new("failed to set auth tag")
    end
  end

  # Reads the authentication tag after `#final` when encrypting.
  def auth_tag(size : Int32 = 16) : Bytes
    raise Error.new("cipher is not authenticated") unless authenticated?
    tag = Bytes.new(size)
    if LibCrypto.evp_cipher_ctx_ctrl(@ctx, EVP_CTRL_GCM_GET_TAG, size, tag.to_unsafe.as(Void*)) != 1
      raise Error.new("failed to get auth tag")
    end
    tag
  end
end

module RingDoorbell::FCM
  # WebPush content encryption — the `aesgcm` scheme from
  # draft-ietf-webpush-encryption-03, which is what FCM uses for push
  # payloads delivered over MCS. Single-record messages only (push payloads
  # are far below the 4096 byte record size).
  module ECE
    extend self

    KEY_LENGTH   = 16
    NONCE_LENGTH = 12
    TAG_LENGTH   = 16

    AUTH_INFO   = "Content-Encoding: auth\0"
    CEK_LABEL   = "Content-Encoding: aesgcm\0"
    NONCE_LABEL = "Content-Encoding: nonce\0"

    # HKDF (RFC 5869) with SHA-256.
    def hkdf(salt : Bytes, ikm : Bytes, info : Bytes, length : Int32) : Bytes
      prk = OpenSSL::HMAC.digest(:sha256, salt, ikm)
      expanded = Bytes.new(0)
      block = Bytes.new(0)
      counter = 1_u8
      while expanded.size < length
        data = IO::Memory.new
        data.write(block)
        data.write(info)
        data.write_byte(counter)
        block = OpenSSL::HMAC.digest(:sha256, prk, data.to_slice)
        joined = Bytes.new(expanded.size + block.size)
        expanded.copy_to(joined)
        block.copy_to(joined + expanded.size)
        expanded = joined
        counter += 1
      end
      expanded[0, length]
    end

    # Decrypts a push payload.
    #
    # - *body* — ciphertext with the 16 byte GCM tag appended
    # - *private_key* — our P-256 key (registered with FCM as `p256dh`)
    # - *public_key* — our uncompressed public key bytes
    # - *auth_secret* — the 16 byte secret registered as `auth`
    # - *dh* — the sender's ephemeral public key (`crypto-key: dh=`)
    # - *salt* — the record salt (`encryption: salt=`)
    def decrypt(body : Bytes, *, private_key : OpenSSL::PKey::EC,
                public_key : Bytes, auth_secret : Bytes,
                dh : Bytes, salt : Bytes) : Bytes
      raise DecryptError.new("payload too short") if body.size < TAG_LENGTH

      key, nonce = derive_key_and_nonce(
        private_key: private_key, local_public: public_key,
        remote_public: dh, auth_secret: auth_secret, salt: salt,
      )

      ciphertext = body[0, body.size - TAG_LENGTH]
      tag = body[body.size - TAG_LENGTH, TAG_LENGTH]

      cipher = OpenSSL::Cipher.new("aes-128-gcm")
      cipher.decrypt
      cipher.key = key
      cipher.iv = nonce
      cipher.auth_tag = tag
      plain = IO::Memory.new
      plain.write(cipher.update(ciphertext))
      begin
        plain.write(cipher.final)
      rescue ex : OpenSSL::Cipher::Error
        raise DecryptError.new("payload failed to authenticate", cause: ex)
      end

      unpad(plain.to_slice)
    end

    # Encrypts *plaintext* the way a push service would — used by the specs'
    # fake servers to produce payloads only the registered keys can decrypt.
    # *private_key* here is the **sender's** ephemeral key (its public part is
    # what arrives in the `dh=` header).
    def encrypt(plaintext : Bytes, *, sender_private_key : OpenSSL::PKey::EC,
                receiver_public : Bytes, auth_secret : Bytes,
                salt : Bytes, pad_length : UInt16 = 0_u16) : Bytes
      receiver_key = OpenSSL::PKey::EC.from_public_bytes(receiver_public, "P-256")
      secret = OpenSSL::PKey::EC.compute_shared_secret(sender_private_key, receiver_key)
      sender_public = sender_private_key.public_key_bytes

      key, nonce = derive_from_secret(
        secret: secret, local_public: receiver_public,
        remote_public: sender_public, auth_secret: auth_secret, salt: salt,
      )

      padded = IO::Memory.new
      padded.write_bytes(pad_length, IO::ByteFormat::BigEndian)
      pad_length.times { padded.write_byte(0_u8) }
      padded.write(plaintext)

      cipher = OpenSSL::Cipher.new("aes-128-gcm")
      cipher.encrypt
      cipher.key = key
      cipher.iv = nonce
      encrypted = IO::Memory.new
      encrypted.write(cipher.update(padded.to_slice))
      encrypted.write(cipher.final)
      encrypted.write(cipher.auth_tag)
      encrypted.to_slice
    end

    private def derive_key_and_nonce(*, private_key, local_public, remote_public, auth_secret, salt)
      remote_key = OpenSSL::PKey::EC.from_public_bytes(remote_public, "P-256")
      secret = OpenSSL::PKey::EC.compute_shared_secret(private_key, remote_key)
      derive_from_secret(
        secret: secret, local_public: local_public,
        remote_public: remote_public, auth_secret: auth_secret, salt: salt,
      )
    rescue ex : OpenSSL::Error
      raise DecryptError.new("key agreement failed: #{ex.message}", cause: ex)
    end

    # Shared HKDF derivation. "local" is always the receiver (the
    # subscription keys), "remote" the sender's ephemeral key — the context
    # orders receiver first regardless of which side we are on.
    private def derive_from_secret(*, secret, local_public, remote_public, auth_secret, salt)
      ikm = hkdf(auth_secret, secret, AUTH_INFO.to_slice, 32)
      context = build_context(local_public, remote_public)
      key = hkdf(salt, ikm, info_with_context(CEK_LABEL, context), KEY_LENGTH)
      nonce = hkdf(salt, ikm, info_with_context(NONCE_LABEL, context), NONCE_LENGTH)
      {key, nonce}
    end

    # context = "P-256" || 0x00 || len16(receiver_pub) || receiver_pub ||
    #           len16(sender_pub) || sender_pub
    private def build_context(receiver_public : Bytes, sender_public : Bytes) : Bytes
      io = IO::Memory.new
      io << "P-256"
      io.write_byte(0_u8)
      io.write_bytes(receiver_public.size.to_u16, IO::ByteFormat::BigEndian)
      io.write(receiver_public)
      io.write_bytes(sender_public.size.to_u16, IO::ByteFormat::BigEndian)
      io.write(sender_public)
      io.to_slice
    end

    private def info_with_context(label : String, context : Bytes) : Bytes
      io = IO::Memory.new
      io << label
      io.write(context)
      io.to_slice
    end

    # Plaintext = len16(padding) || 0x00 * padding || data
    private def unpad(padded : Bytes) : Bytes
      raise DecryptError.new("decrypted record too short") if padded.size < 2
      pad_length = (padded[0].to_i << 8) | padded[1].to_i
      raise DecryptError.new("invalid padding length") if padded.size < 2 + pad_length
      pad_length.times do |i|
        raise DecryptError.new("invalid padding") unless padded[2 + i].zero?
      end
      padded[2 + pad_length, padded.size - 2 - pad_length]
    end
  end
end
