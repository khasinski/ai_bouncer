# frozen_string_literal: true

module AiBouncer
  class Configuration
    # Paths to protect (supports wildcards)
    # Example: ["/login", "/register", "/api/comments", "/api/*"]
    attr_accessor :protected_paths

    # Action to take when attack is detected
    # :block - Return 403 Forbidden
    # :log - Log and continue
    # :challenge - Return custom response (e.g., CAPTCHA redirect)
    attr_accessor :action

    # Threshold for attack detection (0.0 - 1.0)
    # Lower = more sensitive (more false positives)
    # Higher = less sensitive (may miss attacks)
    attr_accessor :threshold

    # Custom response for :block action
    attr_accessor :block_response

    # Custom response for :challenge action
    attr_accessor :challenge_response

    # Logger instance
    attr_accessor :logger

    # Enable/disable the middleware
    attr_accessor :enabled

    # Path to model data directory
    attr_accessor :model_path

    # Storage mode for attack patterns
    # :memory - Keep vectors in memory (faster, uses ~30MB RAM)
    # :database - Use PostgreSQL + pgvector via neighbor gem (scalable, persistent)
    attr_accessor :storage

    # Callback when attack is detected
    # Receives: { request:, classification:, action: }
    attr_accessor :on_attack_detected

    # Callback for all classifications (for monitoring)
    attr_accessor :on_classification

    # Request headers to include in classification
    attr_accessor :include_headers

    # Maximum body size to analyze (bytes)
    attr_accessor :max_body_size

    # Preload model on boot (only for :memory storage)
    # Set to false to lazy-load on first request
    attr_accessor :preload_model

    # Auto-download model files if not present
    # Set to false to disable (will raise error if files missing)
    attr_accessor :auto_download

    # Show download progress messages
    attr_accessor :verbose_download

    def initialize
      @protected_paths = []
      @action = :log
      @threshold = 0.3
      @block_response = { status: 403, body: "Forbidden" }
      @challenge_response = { status: 429, body: "Too Many Requests" }
      @logger = nil
      @enabled = true
      @model_path = nil
      @storage = :memory
      @on_attack_detected = nil
      @on_classification = nil
      @include_headers = %w[User-Agent Content-Type Accept]
      @max_body_size = 10_000
      @preload_model = true
      @auto_download = true
      @verbose_download = true
    end

    def protected_path?(path)
      protected_paths.any? do |pattern|
        if pattern.include?("*")
          File.fnmatch(pattern, path)
        else
          path == pattern || path.start_with?("#{pattern}/")
        end
      end
    end

    def database_storage?
      @storage == :database
    end

    def memory_storage?
      @storage == :memory
    end
  end
end
