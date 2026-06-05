require "socket"

module RingDoorbell::FCM
  # A single MCS socket: TLS to `mtalk.google.com:5228` (plain TCP in specs),
  # sending the login frame and feeding inbound bytes through a `FrameParser`
  # on a background fiber. Lifetime is one connection attempt — the
  # `Listener` creates a fresh instance for every (re)connect.
  class Connection
    Log = RingDoorbell::Log.for("fcm.connection")

    getter? closed = false

    @socket : IO?
    @close_reason : Exception?

    def initialize(@host : String, @port : Int32, @tls : Bool = true,
                   @connect_timeout : Time::Span = 10.seconds)
      @write_mutex = Mutex.new
      @close_channel = Channel(Nil).new(1)
    end

    # Opens the socket, writes the (version-prefixed) login frame and spawns
    # the read loop. Complete inbound frames are yielded to *on_frame* from
    # the read-loop fiber.
    def connect(login_frame : Bytes, &on_frame : (UInt8, Bytes) -> Nil) : Nil
      socket = TCPSocket.new(@host, @port, connect_timeout: @connect_timeout)
      socket.sync = true
      enable_keepalive(socket)
      io = if @tls
             tls_socket(socket)
           else
             socket
           end
      @socket = io
      parser = FrameParser.new(&on_frame)
      write(login_frame)
      spawn { read_loop(io, parser) }
    rescue ex : IO::Error | OpenSSL::Error | Socket::Error
      raise ConnectionError.new("could not connect to #{@host}:#{@port}: #{ex.message}", cause: ex)
    end

    def send_frame(tag : UInt8, message : Protobuf::Message) : Nil
      write(Messages.frame(tag, message))
    end

    # Blocks until the connection is closed (by the server, an error, or
    # `#close`) and returns the reason — `nil` for a deliberate local close.
    def wait_close : Exception?
      @close_channel.receive
      @close_reason
    end

    def close(reason : Exception? = nil) : Nil
      return if @closed
      @closed = true
      @close_reason = reason
      begin
        @socket.try &.close
      rescue IO::Error
        # already torn down
      end
      # Buffered channel: never blocks, and `wait_close` still sees the
      # signal if it subscribes later.
      @close_channel.send(nil)
    end

    # Keep NAT/firewall state alive between push messages — the connection
    # can legitimately sit idle for the full heartbeat interval.
    private def enable_keepalive(socket : TCPSocket) : Nil
      socket.keepalive = true
      socket.tcp_keepalive_idle = 60
      socket.tcp_keepalive_interval = 30
      socket.tcp_keepalive_count = 4
    rescue Socket::Error
      # not supported on this platform — heartbeats still cover liveness
    end

    private def tls_socket(socket : TCPSocket) : IO
      context = OpenSSL::SSL::Context::Client.new
      OpenSSL::SSL::Socket::Client.new(socket, context: context, sync_close: true, hostname: @host)
    end

    private def write(bytes : Bytes) : Nil
      io = @socket
      raise ConnectionError.new("not connected") if io.nil? || closed?
      @write_mutex.synchronize do
        io.write(bytes)
        io.flush
      end
    rescue ex : IO::Error
      error = ConnectionError.new("write failed: #{ex.message}", cause: ex)
      close(error)
      raise error
    end

    private def read_loop(io : IO, parser : FrameParser) : Nil
      buffer = Bytes.new(8192)
      loop do
        count = io.read(buffer)
        break if count.zero?
        parser.push(buffer[0, count])
      end
      close(ConnectionError.new("connection closed by server"))
    rescue ex : IO::Error
      close(closed? ? nil : ConnectionError.new("read failed: #{ex.message}", cause: ex))
    rescue ex : ProtocolError
      close(ex)
    end
  end
end
