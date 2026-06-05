require "base64"
require "json"
require "log"
require "uuid"
require "http/client"
require "openssl"
require "openssl/hmac"
require "openssl_ext"
require "protobuf"

# Client library for Ring doorbells (cloud API).
#
# Authenticate once with `examples/init.cr` (email + password + 2FA) which
# persists a refresh token, then:
#
# ```
# require "ring_doorbell"
#
# client = RingDoorbell::Client.new(token_file: "data/ring.token")
# client.doorbells.each do |bell|
#   puts "#{bell.name}: battery #{bell.battery_level}%"
# end
#
# client.on_ding { |event| puts "DING! #{event.device_name}" }
# client.listen # real-time push notifications via FCM
# ```
#
# Real-time ding events are delivered through Google's FCM push service —
# the library registers itself as a push receiver (the same mechanism the
# official Ring app uses) and holds a persistent connection to
# `mtalk.google.com`. Battery / status are simple REST calls.
module RingDoorbell
  VERSION = "0.1.0"

  Log = ::Log.for("ring_doorbell")
end

require "./ring_doorbell/error"
require "./ring_doorbell/fcm/protos"
require "./ring_doorbell/fcm/credentials"
require "./ring_doorbell/fcm/ece"
require "./ring_doorbell/fcm/frame_parser"
require "./ring_doorbell/fcm/messages"
require "./ring_doorbell/fcm/connection"
require "./ring_doorbell/fcm/registration"
require "./ring_doorbell/fcm/listener"
require "./ring_doorbell/state_file"
require "./ring_doorbell/device"
require "./ring_doorbell/event"
require "./ring_doorbell/auth"
require "./ring_doorbell/rest"
require "./ring_doorbell/client"
