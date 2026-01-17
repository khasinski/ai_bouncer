# frozen_string_literal: true

require "spec_helper"

RSpec.describe AiBouncer do
  let(:model_path) { File.expand_path("../data", __dir__) }

  before do
    AiBouncer.reset!
    AiBouncer.configure do |config|
      config.enabled = true
      config.model_path = model_path
      config.protected_paths = ["/login", "/api/*"]
      config.threshold = 0.3
    end
  end

  describe ".classify" do
    context "with clean request" do
      let(:request_text) do
        AiBouncer.request_to_text(
          method: "POST",
          path: "/login",
          body: "username=john&password=secret123",
          user_agent: "Mozilla/5.0 Chrome/120"
        )
      end

      it "classifies as clean" do
        result = AiBouncer.classify(request_text)

        expect(result[:label]).to eq("clean")
        expect(result[:is_attack]).to be false
        expect(result[:confidence]).to be > 0.5
      end
    end

    context "with SQL injection" do
      let(:request_text) do
        AiBouncer.request_to_text(
          method: "POST",
          path: "/login",
          body: "username=admin'--&password=x",
          user_agent: "python-requests/2.28"
        )
      end

      it "detects SQL injection" do
        result = AiBouncer.classify(request_text)

        expect(result[:is_attack]).to be true
        expect(result[:label]).to eq("sqli")
      end
    end

    context "with XSS" do
      let(:request_text) do
        AiBouncer.request_to_text(
          method: "POST",
          path: "/comments",
          body: '{"text": "<script>alert(1)</script>"}',
          user_agent: "Mozilla/5.0"
        )
      end

      it "detects XSS" do
        result = AiBouncer.classify(request_text)

        expect(result[:is_attack]).to be true
        expect(result[:label]).to eq("xss")
      end
    end

    context "with path traversal" do
      let(:request_text) do
        AiBouncer.request_to_text(
          method: "GET",
          path: "/files/../../../etc/passwd",
          user_agent: "curl/7.68"
        )
      end

      it "detects path traversal" do
        result = AiBouncer.classify(request_text)

        expect(result[:is_attack]).to be true
        expect(result[:label]).to eq("path_traversal")
      end
    end
  end

  describe ".config" do
    it "checks protected paths" do
      expect(AiBouncer.config.protected_path?("/login")).to be true
      expect(AiBouncer.config.protected_path?("/api/users")).to be true
      expect(AiBouncer.config.protected_path?("/home")).to be false
    end
  end

  describe "performance" do
    it "returns latency in result" do
      result = AiBouncer.classify("POST /login username=test")

      expect(result[:latency_ms]).to be_a(Float)
      expect(result[:latency_ms]).to be > 0
    end
  end

  describe "result structure" do
    it "returns expected keys" do
      result = AiBouncer.classify("GET /api/users/123")

      expect(result).to include(
        :label,
        :confidence,
        :is_attack,
        :latency_ms,
        :nearest_distance,
        :neighbors,
        :votes
      )
    end

    it "returns confidence between 0 and 1" do
      result = AiBouncer.classify("POST /login username=test")

      expect(result[:confidence]).to be >= 0
      expect(result[:confidence]).to be <= 1
    end
  end

  describe ".enabled?" do
    it "returns true when configured" do
      expect(AiBouncer.enabled?).to be true
    end

    it "returns false when disabled" do
      AiBouncer.configuration.enabled = false
      expect(AiBouncer.enabled?).to be false
    end
  end
end
