require "./spec_helper"

describe RingDoorbell::Auth do
  it "exchanges email + password for tokens" do
    with_fake_ring do |fake|
      auth = RingDoorbell::Auth.new("hw-1", oauth_url: fake.oauth_url)
      tokens = auth.password_grant(fake.email, fake.password)
      tokens.access_token.should eq("access-1")
      tokens.refresh_token.should eq("refresh-1")
      tokens.expired?.should be_false

      request = fake.requests_to("/oauth/token").first
      request.headers["User-Agent"].should eq("android:com.ringapp")
      request.headers["2fa-support"].should eq("true")
      request.headers["hardware_id"].should eq("hw-1")
      body = JSON.parse(request.body)
      body["grant_type"].should eq("password")
      body["client_id"].should eq("ring_official_android")
      body["scope"].should eq("client")
    end
  end

  it "raises TwoFactorRequired (with delivery details) when Ring wants a code" do
    with_fake_ring do |fake|
      fake.require_2fa = true
      auth = RingDoorbell::Auth.new("hw-1", oauth_url: fake.oauth_url)

      error = expect_raises(RingDoorbell::TwoFactorRequired) do
        auth.password_grant(fake.email, fake.password)
      end
      error.tsv_state.should eq("sms")
      error.phone.should eq("+61xxxxxx89")

      # retrying with the code succeeds
      tokens = auth.password_grant(fake.email, fake.password, fake.two_fa_code)
      tokens.access_token.should_not be_empty
    end
  end

  it "raises AuthError for a wrong 2FA code" do
    with_fake_ring do |fake|
      fake.require_2fa = true
      auth = RingDoorbell::Auth.new("hw-1", oauth_url: fake.oauth_url)
      expect_raises(RingDoorbell::AuthError, /invalid/) do
        auth.password_grant(fake.email, fake.password, "000000")
      end
    end
  end

  it "raises AuthError for bad credentials" do
    with_fake_ring do |fake|
      auth = RingDoorbell::Auth.new("hw-1", oauth_url: fake.oauth_url)
      expect_raises(RingDoorbell::AuthError, /invalid user credentials/) do
        auth.password_grant(fake.email, "wrong")
      end
    end
  end

  it "exchanges a refresh token and rotates it" do
    with_fake_ring do |fake|
      fake.seed_refresh_token("refresh-0")
      auth = RingDoorbell::Auth.new("hw-1", oauth_url: fake.oauth_url)
      tokens = auth.refresh_grant("refresh-0")
      tokens.refresh_token.should_not eq("refresh-0")

      # the old token is no longer valid
      expect_raises(RingDoorbell::AuthError) { auth.refresh_grant("refresh-0") }
      # the rotated one is
      auth.refresh_grant(tokens.refresh_token).access_token.should_not be_empty
    end
  end

  it "raises ConnectionError when the endpoint is unreachable" do
    auth = RingDoorbell::Auth.new("hw-1", oauth_url: "http://127.0.0.1:1/oauth/token")
    expect_raises(RingDoorbell::ConnectionError) do
      auth.password_grant("user@example.com", "pass")
    end
  end
end
