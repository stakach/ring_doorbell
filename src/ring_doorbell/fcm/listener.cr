module RingDoorbell::FCM
  # Maintains the persistent MCS connection that delivers push notifications:
  # login handshake, heartbeats, reconnection with backoff, message dedup and
  # payload decryption. Decrypted notifications are delivered as `JSON::Any`
  # from the connection's read fiber — handlers must not block.
  class Listener
    Log = RingDoorbell::Log.for("fcm.listener")

    DEFAULT_HOST      = "mtalk.google.com"
    DEFAULT_PORT      = 5228
    DEFAULT_HEARTBEAT = 5.minutes
    # Reconnect backoff grows linearly per failed attempt, capped here.
    MAX_RETRY_DELAY = 15.seconds

    getter? running = false

    @connection : Connection?
    @logged_in = false
    @on_notification : Proc(JSON::Any, Nil)?
    @on_persistent_ids : Proc(Array(String), Nil)?
    @on_connected : Proc(Nil)?
    @connected_at : Time::Instant?

    def initialize(@credentials : Credentials,
                   persistent_ids : Array(String) = [] of String, *,
                   @host : String = DEFAULT_HOST,
                   @port : Int32 = DEFAULT_PORT,
                   @tls : Bool = true,
                   @heartbeat_interval : Time::Span = DEFAULT_HEARTBEAT,
                   @login_timeout : Time::Span = 30.seconds,
                   @stale_after : Time::Span = 1.minute,
                   @startup_grace : Time::Span = 2.seconds)
      @persistent_ids = persistent_ids.dup
      @seen_ids = Set(String).new(persistent_ids)
      @private_key = @credentials.ec_private_key
      @public_key = @credentials.public_key_bytes
      @auth_secret = @credentials.auth_secret_bytes
      @state_mutex = Mutex.new
      @last_activity = Time.instant
      @stream_id = 0
      @last_reported_stream_id = -1
    end

    # Called with every decrypted push notification.
    def on_notification(&block : JSON::Any -> Nil) : Nil
      @on_notification = block
    end

    # Called whenever the set of received message ids changes, so the caller
    # can persist them (dedup across restarts / resume on reconnect).
    def on_persistent_ids(&block : Array(String) -> Nil) : Nil
      @on_persistent_ids = block
    end

    # Called after every successful MCS login.
    def on_connected(&block : -> Nil) : Nil
      @on_connected = block
    end

    def start : Nil
      return if @running
      @running = true
      spawn { supervise }
    end

    def stop : Nil
      return unless @running
      @running = false
      @connection.try &.close
    end

    private def supervise : Nil
      retry_count = 0
      while running?
        error = run_connection
        break unless running?
        # A session that logged in successfully resets the backoff — the
        # server rotating long-lived connections (or a NAT dropping an idle
        # one) is routine and must not accumulate delay.
        retry_count = 0 if @logged_in
        retry_count += 1
        delay = {retry_count.seconds, MAX_RETRY_DELAY}.min
        reason = error.try(&.message) || "closed"
        if @logged_in
          Log.info { "push connection ended (#{reason}); reconnecting in #{delay.total_seconds.to_i}s (periodic drops are normal)" }
        else
          Log.warn { "push connection failed before login (#{reason}); reconnecting in #{delay.total_seconds.to_i}s" }
        end
        sleep delay
      end
    rescue ex
      Log.error(exception: ex) { "push listener crashed" }
      @running = false
    end

    # One connection lifetime: connect, login, then block until it drops.
    # Returns the close reason (nil = deliberate stop).
    private def run_connection : Exception?
      reset_connection_state
      connection = Connection.new(@host, @port, @tls)
      @connection = connection
      login_done = Channel(Nil).new(1)

      login = Messages.login_request(
        @credentials.android_id, @credentials.security_token,
        @persistent_ids, @heartbeat_interval,
      )
      connection.connect(Messages.frame(Tag::LOGIN_REQUEST, login, include_version: true)) do |tag, payload|
        handle_frame(connection, tag, payload, login_done)
      end

      select
      when login_done.receive
        # logged in — connection is live
      when timeout(@login_timeout)
        connection.close(TimeoutError.new("MCS login timed out"))
      end

      heartbeat_loop(connection)
      connection.wait_close
    rescue ex : ConnectionError
      ex
    ensure
      @connection = nil
    end

    private def reset_connection_state : Nil
      @stream_id = 0
      @last_reported_stream_id = -1
      @last_activity = Time.instant
      @connected_at = nil
      @logged_in = false
    end

    # Sends a ping after `heartbeat_interval` of silence and tears the
    # connection down when the server stays silent for twice that — runs in
    # its own fiber for the lifetime of *connection*.
    private def heartbeat_loop(connection : Connection) : Nil
      spawn do
        until connection.closed?
          elapsed = Time.instant - @last_activity
          if elapsed >= @heartbeat_interval * 2
            connection.close(TimeoutError.new("no heartbeat from server"))
          elsif elapsed >= @heartbeat_interval
            send_heartbeat_ping(connection)
            sleep @heartbeat_interval
          else
            sleep @heartbeat_interval - elapsed
          end
        end
      end
    end

    private def handle_frame(connection : Connection, tag : UInt8, payload : Bytes, login_done : Channel(Nil)) : Nil
      @last_activity = Time.instant
      case tag
      when Tag::LOGIN_RESPONSE
        handle_login(payload, login_done)
      when Tag::DATA_MESSAGE
        handle_data_message(DataMessageStanza.from_protobuf(IO::Memory.new(payload)))
      when Tag::HEARTBEAT_PING
        ping = HeartbeatPing.from_protobuf(IO::Memory.new(payload))
        connection.send_frame(Tag::HEARTBEAT_ACK, HeartbeatAck.new(
          status: ping.status,
          last_stream_id_received: unreported_stream_id,
        ))
      when Tag::HEARTBEAT_ACK
        Log.debug { "heartbeat acknowledged" }
      when Tag::CLOSE
        connection.close(ConnectionError.new("server requested close"))
      when Tag::STREAM_ERROR
        error = StreamErrorStanza.from_protobuf(IO::Memory.new(payload))
        connection.close(ProtocolError.new("stream error: #{error.type} #{error.text}"))
      else
        Log.debug { "ignoring MCS message with tag #{tag}" }
      end
      @stream_id += 1
    rescue ex : ConnectionError
      # send failed — the connection is already closing; the supervisor
      # handles the reconnect.
    rescue ex
      Log.warn(exception: ex) { "failed to process MCS frame (tag #{tag})" }
    end

    private def handle_login(payload : Bytes, login_done : Channel(Nil)) : Nil
      response = LoginResponse.from_protobuf(IO::Memory.new(payload))
      Log.info { "connected to push service (session #{response.id})" }
      @connected_at = Time.instant
      # The ids we sent with the login request have been delivered.
      update_persistent_ids(&.clear)
      unless @logged_in
        @logged_in = true
        login_done.send(nil)
      end
      @on_connected.try &.call
    end

    private def handle_data_message(message : DataMessageStanza) : Nil
      persistent_id = message.persistent_id
      return if persistent_id && @seen_ids.includes?(persistent_id)

      raw = message.raw_data
      salt = message.crypto_salt
      dh = message.crypto_dh
      unless raw && salt && dh
        Log.debug { "dropping push without an encrypted payload (from #{message.from})" }
        return
      end

      plain = ECE.decrypt(raw, private_key: @private_key, public_key: @public_key,
        auth_secret: @auth_secret, dh: dh, salt: salt)
      notification = JSON.parse(String.new(plain))

      if persistent_id
        @seen_ids << persistent_id
        update_persistent_ids(&.push(persistent_id))
      end

      if reason = stale_reason(message)
        Log.info { "ignoring stale push (#{reason})" }
        return
      end

      @on_notification.try &.call(notification)
    rescue ex : DecryptError
      # Expected occasionally — never fatal, future messages decrypt fine.
      Log.warn { "dropping push that could not be decrypted: #{ex.message}" }
    rescue ex : JSON::ParseException
      Log.warn { "dropping push with unparseable payload: #{ex.message}" }
    end

    # The server re-delivers unacknowledged messages on every login. Old
    # replays must not ring the doorbell, but a press that happened moments
    # ago (e.g. during a reconnect gap) must. The message's `sent` timestamp
    # decides; pushes without one fall back to the post-login grace window.
    private def stale_reason(message : DataMessageStanza) : String?
      sent_ms = message.sent
      if sent_ms && sent_ms > 0
        age = Time.utc - Time.unix_ms(sent_ms)
        return "sent #{age.total_seconds.round.to_i}s ago" if age > @stale_after
        return nil
      end

      if (connected_at = @connected_at) && Time.instant - connected_at < @startup_grace
        return "no timestamp, received immediately after connecting"
      end
      nil
    end

    private def update_persistent_ids(&) : Nil
      ids = @state_mutex.synchronize do
        yield @persistent_ids
        @persistent_ids.dup
      end
      @on_persistent_ids.try &.call(ids)
    end

    # `last_stream_id_received` is only included in heartbeats when it has
    # changed since the last time it was reported.
    private def unreported_stream_id : Int32?
      return nil if @last_reported_stream_id == @stream_id
      @last_reported_stream_id = @stream_id
      @stream_id
    end

    private def send_heartbeat_ping(connection : Connection) : Nil
      connection.send_frame(Tag::HEARTBEAT_PING, HeartbeatPing.new(
        last_stream_id_received: unreported_stream_id,
      ))
    rescue ConnectionError
      # connection is closing; supervisor reconnects
    end
  end
end
