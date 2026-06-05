module RingDoorbell
  # Ring's `clients_api` — devices, health and push-token registration.
  # Handles access-token caching, transparent refresh (60s before expiry or
  # on a 401) and refresh-token rotation.
  class REST
    Log = RingDoorbell::Log.for("rest")

    BASE        = "https://api.ring.com/clients_api"
    API_VERSION = 11

    @token_set : Auth::TokenSet?
    @refresh_token : String?
    @on_refresh_token : Proc(String, Nil)?

    def initialize(@auth : Auth, @hardware_id : String, *,
                   refresh_token : String? = nil,
                   @device_model : String = "ring_doorbell crystal",
                   @base_url : String = BASE)
      @refresh_token = refresh_token
      @token_mutex = Mutex.new
    end

    # Called whenever Ring rotates the refresh token — persist the new value.
    def on_refresh_token(&block : String -> Nil) : Nil
      @on_refresh_token = block
    end

    # Adopt the tokens issued by a fresh password login.
    def apply(tokens : Auth::TokenSet) : Nil
      @token_mutex.synchronize do
        @token_set = tokens
        @refresh_token = tokens.refresh_token
      end
    end

    def authenticated? : Bool
      !@refresh_token.nil?
    end

    # Registers this client install with Ring — required once per session
    # before other endpoints.
    def session : Nil
      request("POST", "/session", {
        device: {
          hardware_id: @hardware_id,
          metadata:    base_metadata,
          os:          "android",
        },
      }.to_json)
    end

    def devices : DeviceList
      DeviceList.from_json(request("GET", "/ring_devices").body)
    end

    # The unparsed device list — handy for inspecting what Ring actually
    # returns for unusual hardware.
    def raw_devices : JSON::Any
      JSON.parse(request("GET", "/ring_devices").body)
    end

    def device_health(doorbot_id : Int64) : Health?
      response = request("GET", "/doorbots/#{doorbot_id}/health")
      HealthResponse.from_json(response.body).device_health
    end

    # Tells Ring to deliver this account's push notifications to our FCM
    # token.
    def register_push(fcm_token : String) : Nil
      request("PATCH", "/device", {
        device: {
          metadata: base_metadata.merge({
            pn_dict_version: "2.0.0",
            pn_service:      "fcm",
          }),
          os:                      "android",
          push_notification_token: fcm_token,
        },
      }.to_json)
    end

    # Subscribes a doorbell so its ding events are pushed.
    def subscribe(doorbot_id : Int64) : Nil
      request("POST", "/doorbots/#{doorbot_id}/subscribe")
    end

    private def base_metadata
      {api_version: API_VERSION, device_model: @device_model}
    end

    private def request(method : String, path : String, body : String? = nil) : HTTP::Client::Response
      response = perform(method, path, body)
      if response.status_code == 401
        # Access token rejected — force a refresh and retry once.
        invalidate_access_token
        response = perform(method, path, body)
      end
      unless response.success?
        raise ResponseError.new("#{method} #{path} failed: HTTP #{response.status_code} #{response.body[0, 200].strip}")
      end
      response
    rescue ex : IO::Error | Socket::Error | OpenSSL::Error
      raise ConnectionError.new("could not reach Ring API: #{ex.message}", cause: ex)
    end

    private def perform(method : String, path : String, body : String?) : HTTP::Client::Response
      headers = HTTP::Headers{
        "Authorization" => "Bearer #{access_token}",
        "User-Agent"    => Auth::USER_AGENT,
        "hardware_id"   => @hardware_id,
        "Accept"        => "application/json",
      }
      headers["Content-Type"] = "application/json" if body
      HTTP::Client.exec(method, "#{@base_url}#{path}", headers: headers, body: body)
    end

    private def access_token : String
      @token_mutex.synchronize do
        tokens = @token_set
        return tokens.access_token if tokens && !tokens.expired?

        refresh_token = @refresh_token
        raise AuthError.new("not authenticated — log in first (see examples/init.cr)") unless refresh_token

        tokens = @auth.refresh_grant(refresh_token)
        @token_set = tokens
        if tokens.refresh_token != refresh_token
          @refresh_token = tokens.refresh_token
          @on_refresh_token.try &.call(tokens.refresh_token)
        end
        tokens.access_token
      end
    end

    private def invalidate_access_token : Nil
      @token_mutex.synchronize { @token_set = nil }
    end
  end
end
