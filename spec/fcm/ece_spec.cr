require "../spec_helper"

private alias ECE = RingDoorbell::FCM::ECE

private record EceSetup,
  receiver_private : OpenSSL::PKey::EC,
  receiver_public : Bytes,
  sender : OpenSSL::PKey::EC,
  auth_secret : Bytes,
  salt : Bytes

private def ece_setup : EceSetup
  receiver = OpenSSL::PKey::EC.generate("P-256")
  EceSetup.new(
    receiver_private: receiver,
    receiver_public: receiver.public_key_bytes,
    sender: OpenSSL::PKey::EC.generate("P-256"),
    auth_secret: Random::Secure.random_bytes(16),
    salt: Random::Secure.random_bytes(16),
  )
end

describe RingDoorbell::FCM::ECE do
  it "round-trips an encrypted payload" do
    setup = ece_setup
    plaintext = %({"data":{"android_config":"{}"}})

    body = ECE.encrypt(plaintext.to_slice,
      sender_private_key: setup.sender,
      receiver_public: setup.receiver_public,
      auth_secret: setup.auth_secret,
      salt: setup.salt)

    decrypted = ECE.decrypt(body,
      private_key: setup.receiver_private,
      public_key: setup.receiver_public,
      auth_secret: setup.auth_secret,
      dh: setup.sender.public_key_bytes,
      salt: setup.salt)

    String.new(decrypted).should eq(plaintext)
  end

  it "strips record padding" do
    setup = ece_setup
    body = ECE.encrypt("ding".to_slice,
      sender_private_key: setup.sender,
      receiver_public: setup.receiver_public,
      auth_secret: setup.auth_secret,
      salt: setup.salt,
      pad_length: 16_u16)

    decrypted = ECE.decrypt(body,
      private_key: setup.receiver_private,
      public_key: setup.receiver_public,
      auth_secret: setup.auth_secret,
      dh: setup.sender.public_key_bytes,
      salt: setup.salt)

    String.new(decrypted).should eq("ding")
  end

  it "rejects tampered ciphertext" do
    setup = ece_setup
    body = ECE.encrypt("payload".to_slice,
      sender_private_key: setup.sender,
      receiver_public: setup.receiver_public,
      auth_secret: setup.auth_secret,
      salt: setup.salt)
    body[3] ^= 0xFF_u8

    expect_raises(RingDoorbell::DecryptError) do
      ECE.decrypt(body,
        private_key: setup.receiver_private,
        public_key: setup.receiver_public,
        auth_secret: setup.auth_secret,
        dh: setup.sender.public_key_bytes,
        salt: setup.salt)
    end
  end

  it "rejects payloads encrypted with a different auth secret" do
    setup = ece_setup
    body = ECE.encrypt("payload".to_slice,
      sender_private_key: setup.sender,
      receiver_public: setup.receiver_public,
      auth_secret: Random::Secure.random_bytes(16),
      salt: setup.salt)

    expect_raises(RingDoorbell::DecryptError) do
      ECE.decrypt(body,
        private_key: setup.receiver_private,
        public_key: setup.receiver_public,
        auth_secret: setup.auth_secret,
        dh: setup.sender.public_key_bytes,
        salt: setup.salt)
    end
  end

  it "rejects truncated payloads" do
    setup = ece_setup
    expect_raises(RingDoorbell::DecryptError, /too short/) do
      ECE.decrypt(Bytes[1, 2, 3],
        private_key: setup.receiver_private,
        public_key: setup.receiver_public,
        auth_secret: setup.auth_secret,
        dh: setup.sender.public_key_bytes,
        salt: setup.salt)
    end
  end

  it "rejects garbage sender keys" do
    setup = ece_setup
    expect_raises(RingDoorbell::DecryptError) do
      ECE.decrypt(Bytes.new(32),
        private_key: setup.receiver_private,
        public_key: setup.receiver_public,
        auth_secret: setup.auth_secret,
        dh: Bytes.new(65), # not a valid curve point
        salt: setup.salt)
    end
  end
end
