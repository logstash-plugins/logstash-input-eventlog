require "logstash/devutils/rspec/spec_helper"
require 'logstash/inputs/eventlog'

describe LogStash::Inputs::EventLog, :windows => true do
  it_behaves_like "an interruptible input plugin" do
    let(:config) { { "logfile" => "Application" } }
  end
end
