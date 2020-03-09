require "logstash/devutils/rspec/spec_helper"
require "logstash/devutils/rspec/shared_examples"

describe "LogStash::Inputs::EventLog", :windows => true do

  before(:all) do
    require 'logstash/inputs/eventlog'
  end

  it_behaves_like "an interruptible input plugin" do
    let(:config) { { "logfile" => "Application", "interval" => 10000000 } }
  end
end
