module RingDoorbell
  # The public entry point — composes authentication, the Ring REST API and
  # the FCM push listener behind a small surface:
  #
  # ```
  # client = RingDoorbell::Client.new(token_file: "data/ring.token")
  # client.doorbells.each { |bell| puts bell.name }
  # client.on_ding { |event| puts "DING from #{event.device_name}" }
  # client.listen
  # ```
  #
  # All state that must survive restarts (refresh token, hardware id, push
  # credentials, received message ids) lives in the JSON `token_file`.
  class Client
    Log = RingDoorbell::Log.for("client")

    DEVICE_MODEL = "ring_doorbell crystal"

    # Ring's Firebase project — push notifications for the official Android
    # app are registered against it.
    RING_FIREBASE_API_KEY    = "AIzaSyCv-hdFBmmdBBJadNy-TFwB-xN_H5m3Bk8"
    RING_FIREBASE_PROJECT_ID = "ring-17770"
    RING_FIREBASE_APP_ID     = "1:876313859327:android:e10ec6ddb3c81f39"

    @listener : FCM::Listener?
    @on_ding : Proc(DingEvent, Nil)?
    @on_motion : Proc(DingEvent, Nil)?
    @on_event : Proc(DingEvent, Nil)?

    def initialize(*, @token_file : String,
                   @device_model : String = DEVICE_MODEL,
                   oauth_url : String = Auth::OAUTH_URL,
                   rest_base : String = REST::BASE,
                   @mcs_host : String = FCM::Listener::DEFAULT_HOST,
                   @mcs_port : Int32 = FCM::Listener::DEFAULT_PORT,
                   @mcs_tls : Bool = true,
                   @checkin_url : String = FCM::Registration::CHECKIN_URL,
                   @register_url : String = FCM::Registration::REGISTER_URL,
                   @fis_base : String = FCM::Registration::FIS_BASE,
                   @fcm_base : String = FCM::Registration::FCM_BASE,
                   @heartbeat_interval : Time::Span = FCM::Listener::DEFAULT_HEARTBEAT,
                   @login_timeout : Time::Span = 30.seconds,
                   @stale_after : Time::Span = 1.minute,
                   @startup_grace : Time::Span = 2.seconds)
      @state = StateFile.load(@token_file)
      @auth = Auth.new(@state.hardware_id, oauth_url: oauth_url)
      @rest = REST.new(@auth, @state.hardware_id,
        refresh_token: @state.refresh_token,
        device_model: @device_model,
        base_url: rest_base)
      @rest.on_refresh_token do |token|
        @state.refresh_token = token
        save_state
      end
    end

    # ----- authentication -----

    # Email + password login; raises `TwoFactorRequired` when Ring wants a
    # verification code — retry with `code:` set. On success the rotated
    # refresh token is persisted to the token file.
    def login(email : String, password : String, code : String? = nil) : Nil
      tokens = @auth.password_grant(email, password, code)
      @rest.apply(tokens)
      @state.refresh_token = tokens.refresh_token
      save_state
    end

    def authenticated? : Bool
      @rest.authenticated?
    end

    # ----- devices / status -----

    # All doorbells on the account (owned, shared and "other" devices such as
    # intercoms / audio-only units).
    def doorbells : Array(Doorbell)
      @rest.devices.doorbells
    end

    def doorbell(id : Int64) : Doorbell?
      doorbells.find { |device| device.id == id }
    end

    # Battery percentage from the device health endpoint (more current than
    # the value embedded in the device list).
    def battery_level(id : Int64) : Int32?
      @rest.device_health(id).try(&.battery_percentage)
    end

    # The unparsed `ring_devices` payload — for inspecting unusual hardware.
    def raw_devices : JSON::Any
      @rest.raw_devices
    end

    # ----- real-time events -----

    # Someone pressed the doorbell. Called from the push read fiber — keep
    # handlers quick, or `spawn` long-running work.
    def on_ding(&block : DingEvent -> Nil) : Nil
      @on_ding = block
    end

    def on_motion(&block : DingEvent -> Nil) : Nil
      @on_motion = block
    end

    # Every recognised push notification, including kinds not surfaced via
    # `on_ding` / `on_motion`.
    def on_event(&block : DingEvent -> Nil) : Nil
      @on_event = block
    end

    # Connects to the push service and starts delivering events. The first
    # call creates and persists the FCM push credentials, registers the push
    # token with Ring and subscribes each doorbell. Returns once the listener
    # is started (it reconnects in the background as needed).
    def listen : Nil
      return if listening?
      raise AuthError.new("not authenticated — log in first (see examples/init.cr)") unless authenticated?

      credentials = ensure_fcm_credentials
      @rest.session
      @rest.register_push(credentials.fcm_token)
      subscribe_doorbells

      listener = FCM::Listener.new(credentials, @state.persistent_ids,
        host: @mcs_host, port: @mcs_port, tls: @mcs_tls,
        heartbeat_interval: @heartbeat_interval,
        login_timeout: @login_timeout,
        stale_after: @stale_after,
        startup_grace: @startup_grace)
      listener.on_persistent_ids do |ids|
        @state.persistent_ids = ids
        save_state
      end
      listener.on_notification { |notification| dispatch(notification) }
      @listener = listener
      listener.start
    end

    def stop : Nil
      @listener.try &.stop
      @listener = nil
    end

    def listening? : Bool
      @listener.try(&.running?) || false
    end

    private def ensure_fcm_credentials : FCM::Credentials
      if credentials = @state.fcm
        begin
          # Periodic check-in keeps the device identity alive.
          registration.checkin(credentials)
        rescue ex : Error
          Log.warn { "push check-in failed (#{ex.message}) — continuing with existing credentials" }
        end
        return credentials
      end

      Log.info { "registering as a new push receiver (first run)" }
      credentials = registration.register
      @state.fcm = credentials
      save_state
      credentials
    end

    private def registration : FCM::Registration
      FCM::Registration.new(
        api_key: RING_FIREBASE_API_KEY,
        project_id: RING_FIREBASE_PROJECT_ID,
        app_id: RING_FIREBASE_APP_ID,
        checkin_url: @checkin_url,
        register_url: @register_url,
        fis_base: @fis_base,
        fcm_base: @fcm_base,
      )
    end

    private def subscribe_doorbells : Nil
      doorbells.each do |device|
        @rest.subscribe(device.id)
      rescue ex : Error
        # Shared devices can refuse the subscription — events may still
        # arrive via the owner's subscription.
        Log.warn { "could not subscribe #{device.name || device.id}: #{ex.message}" }
      end
    end

    private def dispatch(notification : JSON::Any) : Nil
      event = DingEvent.from_push(notification)
      unless event
        Log.debug { "ignoring push without a data envelope" }
        return
      end
      Log.debug { "push event: #{event.kind} from #{event.device_name || event.device_id}" }
      @on_event.try &.call(event)
      if event.ding?
        @on_ding.try &.call(event)
      elsif event.motion?
        @on_motion.try &.call(event)
      end
    rescue ex
      Log.error(exception: ex) { "event handler raised" }
    end

    private def save_state : Nil
      @state.save(@token_file)
    end
  end
end
