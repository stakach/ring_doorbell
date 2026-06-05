# An in-process stand-in for the Ring cloud (oauth + clients_api) and the
# Google registration endpoints (checkin / c2dm / FIS / FCM), so specs cover
# the full HTTP surface without touching the network.
class FakeRing
  record Request,
    method : String,
    path : String,
    body : String,
    headers : HTTP::Headers

  getter port : Int32 = 0
  getter requests = [] of Request
  getter checkin_count = 0

  # --- behaviour switches ---
  property email = "user@example.com"
  property password = "sekret"
  property? require_2fa = false
  property two_fa_code = "123456"
  # Number of times c2dm/register3 fails before succeeding.
  property gcm_register_failures = 0

  # The device list served by /clients_api/ring_devices.
  property devices_json : String = {
    doorbots: [{
      id:           111_222,
      kind:         "doorbell_v3",
      description:  "Front Door",
      battery_life: "71",
      alerts:       {connection: "online"},
      health:       {battery_percentage: 71},
    }],
    authorized_doorbots: [] of Nil,
    chimes:              [] of Nil,
    stickup_cams:        [] of Nil,
    other:               [] of Nil,
  }.to_json
  property health_battery : Int32 = 81

  @server : HTTP::Server?
  @mutex = Mutex.new
  @token_counter = 0
  @valid_access = Set(String).new
  @valid_refresh = Set(String).new

  # Registers a refresh token as valid (as if issued by an earlier login).
  def seed_refresh_token(token : String) : Nil
    @mutex.synchronize { @valid_refresh << token }
  end

  # Invalidate all access tokens — the next API call gets a 401 and must
  # refresh.
  def revoke_access_tokens! : Nil
    @mutex.synchronize { @valid_access.clear }
  end

  def start : Int32
    server = HTTP::Server.new { |context| handle(context) }
    @server = server
    address = server.bind_tcp("127.0.0.1", 0)
    @port = address.port
    spawn do
      server.listen
    rescue
      # closed during teardown before the fiber got to run
    end
    @port
  end

  def stop : Nil
    @server.try &.close
  rescue
    # already closed
  end

  def base_url : String
    "http://127.0.0.1:#{port}"
  end

  def oauth_url : String
    "#{base_url}/oauth/token"
  end

  def rest_base : String
    "#{base_url}/clients_api"
  end

  def checkin_url : String
    "#{base_url}/google/checkin"
  end

  def register_url : String
    "#{base_url}/google/c2dm/register3"
  end

  def fis_base : String
    "#{base_url}/google/fis"
  end

  def fcm_base : String
    "#{base_url}/google/fcm"
  end

  def requests_to(path : String) : Array(Request)
    @mutex.synchronize { @requests.select { |request| request.path == path } }
  end

  def last_refresh_token : String?
    @mutex.synchronize { @valid_refresh.to_a.last? }
  end

  private def handle(context : HTTP::Server::Context) : Nil
    request = context.request
    body = request.body.try(&.gets_to_end) || ""
    @mutex.synchronize do
      @requests << Request.new(request.method, request.path, body, request.headers.dup)
    end

    case {request.method, request.path}
    when {"POST", "/oauth/token"}
      handle_oauth(context, body)
    when {"POST", "/google/checkin"}
      handle_checkin(context)
    when {"POST", "/google/c2dm/register3"}
      handle_gcm_register(context, body)
    when {"POST", "/google/fis/projects/ring-17770/installations"}
      json(context, 200, {
        authToken:    {token: "fis-auth-token", expiresIn: "604800s"},
        refreshToken: "fis-refresh-token",
        fid:          "spec-fid",
      }.to_json)
    when {"POST", "/google/fcm/projects/ring-17770/registrations"}
      handle_fcm_register(context, body)
    else
      handle_clients_api(context, body)
    end
  end

  private def handle_oauth(context, body : String) : Nil
    grant = JSON.parse(body)
    case grant["grant_type"]?.try(&.as_s)
    when "password"
      unless grant["username"]? == @email && grant["password"]? == @password
        return json(context, 401, {error: "access_denied", error_description: "invalid user credentials"}.to_json)
      end
      if @require_2fa
        code = context.request.headers["2fa-code"]?
        if code.nil? || code.empty?
          return json(context, 412, {next_time_in_secs: 60, phone: "+61xxxxxx89", tsv_state: "sms"}.to_json)
        elsif code != @two_fa_code
          return json(context, 400, {error: "Verification Code is invalid or expired"}.to_json)
        end
      end
      issue_tokens(context)
    when "refresh_token"
      token = grant["refresh_token"]?.try(&.as_s)
      valid = @mutex.synchronize { token && @valid_refresh.includes?(token) }
      if valid
        @mutex.synchronize { @valid_refresh.delete(token) }
        issue_tokens(context)
      else
        json(context, 401, {error: "invalid_grant"}.to_json)
      end
    else
      json(context, 400, {error: "unsupported_grant_type"}.to_json)
    end
  end

  private def issue_tokens(context) : Nil
    access, refresh = @mutex.synchronize do
      @token_counter += 1
      new_access = "access-#{@token_counter}"
      new_refresh = "refresh-#{@token_counter}"
      @valid_access << new_access
      @valid_refresh << new_refresh
      {new_access, new_refresh}
    end
    json(context, 200, {
      access_token:  access,
      refresh_token: refresh,
      expires_in:    3600,
      scope:         "client",
      token_type:    "Bearer",
    }.to_json)
  end

  private def handle_checkin(context) : Nil
    @mutex.synchronize { @checkin_count += 1 }
    response = RingDoorbell::FCM::AndroidCheckinResponse.new(
      stats_ok: true,
      android_id: 5_752_962_939_u64,
      security_token: 1_234_509_876_u64,
    )
    context.response.content_type = "application/x-protobuf"
    context.response.write(response.to_protobuf.to_slice)
  end

  private def handle_gcm_register(context, body : String) : Nil
    unless context.request.headers["Authorization"]?.try(&.starts_with?("AidLogin "))
      return json(context, 401, "Error=AUTHENTICATION_FAILED")
    end
    failures = @mutex.synchronize do
      remaining = @gcm_register_failures
      @gcm_register_failures -= 1 if remaining.positive?
      remaining
    end
    if failures.positive?
      context.response.print("Error=PHONE_REGISTRATION_ERROR")
    else
      context.response.print("token=fake-gcm-token")
    end
  end

  private def handle_fcm_register(context, body : String) : Nil
    payload = JSON.parse(body)
    web = payload["web"]?
    if web.nil? || web["auth"]?.nil? || web["p256dh"]?.nil? || web["endpoint"]?.nil?
      return json(context, 400, {error: {message: "missing web push parameters"}}.to_json)
    end
    json(context, 200, {token: "fake-fcm-token"}.to_json)
  end

  private def handle_clients_api(context, body : String) : Nil
    request = context.request
    unless authorized?(request)
      return json(context, 401, {error: "unauthorized"}.to_json)
    end

    case {request.method, request.path}
    when {"POST", "/clients_api/session"}
      json(context, 201, {profile: {id: 42}}.to_json)
    when {"GET", "/clients_api/ring_devices"}
      json(context, 200, @devices_json)
    when {"PATCH", "/clients_api/device"}
      json(context, 204, "")
    else
      if request.method == "GET" && request.path =~ %r{^/clients_api/doorbots/(\d+)/health$}
        # NOTE: the real /health endpoint reports battery_percentage as a
        # STRING (observed on a Ring Intercom) even though the embedded
        # health object in ring_devices uses an integer.
        json(context, 200, {device_health: {battery_percentage: @health_battery.to_s, battery_voltage: 3876.0}}.to_json)
      elsif request.method == "POST" && request.path =~ %r{^/clients_api/doorbots/(\d+)/subscribe$}
        json(context, 204, "")
      else
        json(context, 404, {error: "not found"}.to_json)
      end
    end
  end

  private def authorized?(request : HTTP::Request) : Bool
    header = request.headers["Authorization"]? || return false
    token = header.lchop("Bearer ")
    @mutex.synchronize { @valid_access.includes?(token) }
  end

  private def json(context, status : Int32, body : String) : Nil
    context.response.status_code = status
    context.response.content_type = "application/json"
    context.response.print(body)
  end
end

# Boots a `FakeRing`, yields it, and tears it down.
def with_fake_ring(&)
  fake = FakeRing.new
  fake.start
  begin
    yield fake
  ensure
    fake.stop
  end
end
