# Prints doorbell presses (and motion) in real time via FCM push.
#
#   crystal run examples/listen.cr -- [token_file]
#
# Set LOG_LEVEL=debug to watch the push protocol at work.
require "../src/ring_doorbell"

::Log.setup_from_env(default_level: :info)

token_file = ARGV[0]? || "data/ring.token"
client = RingDoorbell::Client.new(token_file: token_file)
abort "not authenticated — run examples/init.cr first" unless client.authenticated?

puts "Doorbells:"
client.doorbells.each do |bell|
  battery = bell.battery_level.try { |level| "#{level}%" } || "n/a"
  status = bell.online? ? "online" : "offline"
  puts "  ##{bell.id} #{bell.name} (#{bell.kind}) — #{status}, battery #{battery}"
end

client.on_ding do |event|
  puts "[#{Time.local}] 🔔 DING! #{event.device_name || event.device_id} (#{event.subtype || event.kind})"
end

client.on_motion do |event|
  puts "[#{Time.local}] 🚶 motion at #{event.device_name || event.device_id}"
end

client.on_event do |event|
  next if event.ding? || event.motion?
  puts "[#{Time.local}] event: #{event.kind} #{event.raw.to_json[0, 200]}"
end

client.listen
puts "Listening for dings — press the doorbell! (Ctrl+C to exit)"

Process.on_terminate do
  puts "shutting down"
  client.stop
  exit
end

sleep
