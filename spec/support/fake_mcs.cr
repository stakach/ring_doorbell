# An in-process MCS push server (plain TCP — listeners connect with
# `tls: false` in specs). Accepts logins, answers heartbeats and pushes
# encrypted notifications exactly the way `mtalk.google.com` does.
class FakeMCS
  private class ClientState
    getter socket : TCPSocket
    property? version_sent = false

    def initialize(@socket)
    end
  end

  getter port : Int32 = 0
  getter login_requests = [] of RingDoorbell::FCM::LoginRequest
  getter heartbeat_pings = [] of RingDoorbell::FCM::HeartbeatPing
  getter heartbeat_acks = [] of RingDoorbell::FCM::HeartbeatAck

  @server : TCPServer?
  @clients = [] of ClientState
  @mutex = Mutex.new
  @message_counter = 0

  # *credentials* are the client's push keys — pushes are encrypted for them.
  # Reassignable for flows where the client registers (generating keys) only
  # after the fake server is already running.
  property credentials : RingDoorbell::FCM::Credentials

  def initialize(@credentials : RingDoorbell::FCM::Credentials)
  end

  def start : Int32
    server = TCPServer.new("127.0.0.1", 0)
    @server = server
    @port = server.local_address.port
    spawn { accept_loop(server) }
    @port
  end

  def stop : Nil
    @server.try &.close
    drop_clients
  rescue IO::Error
    # already closed
  end

  def client_count : Int32
    @mutex.synchronize { @clients.size }
  end

  # Forcibly close every client socket (without stopping the server) — the
  # listener should reconnect.
  def drop_clients : Nil
    sockets = @mutex.synchronize do
      states = @clients.dup
      @clients.clear
      states
    end
    sockets.each do |state|
      state.socket.close rescue nil
    end
  end

  # Encrypts *plaintext* for the registered keys and pushes it to every
  # connected client. Returns the persistent id used. *sent* mirrors the
  # server-side send timestamp carried by real messages (nil = omitted).
  def push(plaintext : String, persistent_id : String? = nil,
           sent : Time? = Time.utc) : String?
    persistent_id ||= @mutex.synchronize { "spec-msg-#{@message_counter += 1}" }
    sender = OpenSSL::PKey::EC.generate("P-256")
    salt = Random::Secure.random_bytes(16)
    ciphertext = RingDoorbell::FCM::ECE.encrypt(plaintext.to_slice,
      sender_private_key: sender,
      receiver_public: @credentials.public_key_bytes,
      auth_secret: @credentials.auth_secret_bytes,
      salt: salt)

    encode = ->(bytes : Bytes) { RingDoorbell::FCM::Credentials.encode(bytes) }
    push_message(RingDoorbell::FCM::DataMessageStanza.new(
      id: persistent_id,
      from: "876313859327",
      category: "com.ring.android",
      app_data: [
        RingDoorbell::FCM::AppData.new(key: "encryption", value: "salt=#{encode.call(salt)}"),
        RingDoorbell::FCM::AppData.new(key: "crypto-key", value: "dh=#{encode.call(sender.public_key_bytes)}"),
      ],
      persistent_id: persistent_id,
      sent: sent.try(&.to_unix_ms),
      raw_data: ciphertext,
    ))
    persistent_id
  end

  # Pushes an arbitrary (possibly malformed) data message.
  def push_message(message : RingDoorbell::FCM::DataMessageStanza) : Nil
    broadcast(RingDoorbell::FCM::Tag::DATA_MESSAGE, message)
  end

  def send_ping : Nil
    broadcast(RingDoorbell::FCM::Tag::HEARTBEAT_PING, RingDoorbell::FCM::HeartbeatPing.new(stream_id: 1))
  end

  def send_close : Nil
    broadcast(RingDoorbell::FCM::Tag::CLOSE, RingDoorbell::FCM::Close.new)
  end

  private def broadcast(tag : UInt8, message : Protobuf::Message) : Nil
    states = @mutex.synchronize { @clients.dup }
    states.each { |state| send_frame(state, tag, message) }
  end

  private def accept_loop(server : TCPServer) : Nil
    while socket = server.accept?
      state = ClientState.new(socket)
      @mutex.synchronize { @clients << state }
      spawn { serve_client(state) }
    end
  end

  private def serve_client(state : ClientState) : Nil
    parser = RingDoorbell::FCM::FrameParser.new do |tag, payload|
      handle_frame(state, tag, payload)
    end
    buffer = Bytes.new(4096)
    loop do
      count = state.socket.read(buffer)
      break if count.zero?
      parser.push(buffer[0, count])
    end
  rescue IO::Error | RingDoorbell::ProtocolError
    # client went away
  ensure
    @mutex.synchronize { @clients.delete(state) }
    state.socket.close rescue nil
  end

  private def handle_frame(state : ClientState, tag : UInt8, payload : Bytes) : Nil
    case tag
    when RingDoorbell::FCM::Tag::LOGIN_REQUEST
      login = RingDoorbell::FCM::LoginRequest.from_protobuf(IO::Memory.new(payload))
      @mutex.synchronize { @login_requests << login }
      send_frame(state, RingDoorbell::FCM::Tag::LOGIN_RESPONSE,
        RingDoorbell::FCM::LoginResponse.new(id: "spec-session", server_timestamp: 1_750_000_000_000_i64))
    when RingDoorbell::FCM::Tag::HEARTBEAT_PING
      ping = RingDoorbell::FCM::HeartbeatPing.from_protobuf(IO::Memory.new(payload))
      @mutex.synchronize { @heartbeat_pings << ping }
      send_frame(state, RingDoorbell::FCM::Tag::HEARTBEAT_ACK, RingDoorbell::FCM::HeartbeatAck.new)
    when RingDoorbell::FCM::Tag::HEARTBEAT_ACK
      ack = RingDoorbell::FCM::HeartbeatAck.from_protobuf(IO::Memory.new(payload))
      @mutex.synchronize { @heartbeat_acks << ack }
    end
  end

  private def send_frame(state : ClientState, tag : UInt8, message : Protobuf::Message) : Nil
    include_version = !state.version_sent?
    state.version_sent = true
    bytes = RingDoorbell::FCM::Messages.frame(tag, message, include_version: include_version)
    @mutex.synchronize do
      state.socket.write(bytes)
      state.socket.flush
    end
  rescue IO::Error
    # client went away
  end
end

# Boots a `FakeMCS` for *credentials*, yields it, and tears it down.
def with_fake_mcs(credentials : RingDoorbell::FCM::Credentials, &)
  fake = FakeMCS.new(credentials)
  fake.start
  begin
    yield fake
  ensure
    fake.stop
  end
end
