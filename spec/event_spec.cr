require "./spec_helper"

private def parse_event(plaintext : String) : RingDoorbell::DingEvent
  RingDoorbell::DingEvent.from_push(JSON.parse(plaintext)) || fail "expected a parseable event"
end

describe RingDoorbell::DingEvent do
  it "parses a v2 ding notification (JSON-string data values)" do
    event = parse_event(spec_ding_plaintext)
    event.kind.ding?.should be_true
    event.ding?.should be_true
    event.motion?.should be_false
    event.device_id.should eq(123_456)
    event.device_name.should eq("Front Door")
    event.device_kind.should eq("doorbell_v3")
    event.event_id.should eq("7654321234567890123")
    event.created_at.should eq("2026-06-05T10:00:00Z")
    event.subtype.should eq("ding")
  end

  it "classifies motion events" do
    plaintext = spec_ding_plaintext(category: "com.ring.pn.live-event.motion")
    event = parse_event(plaintext)
    event.kind.motion?.should be_true
    event.motion?.should be_true
    event.ding?.should be_false
  end

  it "treats intercom buzzes as dings" do
    plaintext = spec_ding_plaintext(category: "com.ring.pn.live-event.intercom")
    event = parse_event(plaintext)
    event.kind.intercom?.should be_true
    event.ding?.should be_true
  end

  it "classifies unknown categories as Other" do
    plaintext = spec_ding_plaintext(category: "com.ring.push.SOMETHING_ELSE")
    event = parse_event(plaintext)
    event.kind.other?.should be_true
    event.ding?.should be_false
  end

  it "returns nil for pushes without a data envelope" do
    RingDoorbell::DingEvent.from_push(JSON.parse(%({"foo": "bar"}))).should be_nil
  end

  it "keeps unparseable data values as raw strings" do
    payload = {data: {"android_config" => {category: "com.ring.pn.live-event.ding"}.to_json,
                      "free_text" => "not json at all"}}.to_json
    event = parse_event(payload)
    event.kind.ding?.should be_true
    event.raw["free_text"].as_s.should eq("not json at all")
  end

  it "surfaces the decoded notification via #raw" do
    event = parse_event(spec_ding_plaintext)
    event.raw.dig("analytics", "server_id").as_s.should eq("com.ring.pns")
  end
end
