# frozen_string_literal: true

# AiBouncer configuration
# https://github.com/khasinski/ai_bouncer

AiBouncer.configure do |config|
  # Enable/disable the middleware
  config.enabled = Rails.env.production? || Rails.env.staging?

  # Storage mode for attack pattern vectors:
  #
  # :memory   - Keep vectors in memory (default)
  #             Pros: Fast (~2ms), no database required
  #             Cons: Uses ~30MB RAM, not scalable to custom patterns
  #
  # :database - Use PostgreSQL + pgvector via neighbor gem
  #             Pros: Scalable, can add custom patterns, persistent
  #             Cons: Requires pgvector extension, slightly slower (~5ms)
  #
  # For :database mode, you need:
  #   1. Add to Gemfile: gem "neighbor"
  #   2. Install pgvector: https://github.com/pgvector/pgvector
  #   3. Run: rails generate ai_bouncer:migration
  #   4. Run: rails db:migrate
  #   5. Run: rails ai_bouncer:seed
  #
  config.storage = :memory

  # Paths to protect (supports wildcards)
  # Only used by middleware - controller concern ignores this
  config.protected_paths = [
    "/login",
    "/signin",
    "/register",
    "/signup",
    "/api/sessions",
    "/api/users",
    # "/api/*",  # Uncomment to protect all API routes
  ]

  # Action when attack is detected:
  # :block     - Return 403 Forbidden
  # :challenge - Return custom response (e.g., redirect to CAPTCHA)
  # :log       - Log and continue (for testing)
  config.action = :log  # Start with :log, switch to :block when confident

  # Detection threshold (0.0 - 1.0)
  # Lower = more sensitive (may have false positives)
  # Higher = less sensitive (may miss some attacks)
  config.threshold = 0.3

  # Path to model files (ONNX model + tokenizer)
  # For :memory mode, also needs vectors.bin and labels.json
  config.model_path = Rails.root.join("vendor", "ai_bouncer")

  # Auto-download model files from GitHub if not present
  # On first request, model files (~33MB) will be downloaded automatically
  config.auto_download = true

  # Preload model on boot (only for :memory storage)
  # Set to false to lazy-load on first request (faster boot, slower first request)
  config.preload_model = true

  # Use Rails logger
  config.logger = Rails.logger

  # Custom block response
  config.block_response = {
    status: 403,
    body: "Forbidden"
  }

  # Custom challenge response (e.g., for CAPTCHA redirect)
  config.challenge_response = {
    status: 429,
    body: "Too Many Requests",
    # redirect_to: "/challenge"  # Uncomment to redirect instead
  }

  # Callback when attack is detected
  config.on_attack_detected = ->(request:, classification:, action:) {
    # Log to your security monitoring system
    # SecurityMonitor.log_attack(
    #   ip: request.ip,
    #   path: request.path,
    #   label: classification[:label],
    #   confidence: classification[:confidence]
    # )

    # Or send to Slack/PagerDuty for high-severity attacks
    # if classification[:label].in?(%w[sqli command_injection])
    #   SlackNotifier.alert("Attack detected: #{classification[:label]}")
    # end
  }

  # Optional: Callback for all classifications (for monitoring/metrics)
  # config.on_classification = ->(request:, classification:) {
  #   StatsD.timing("ai_bouncer.latency", classification[:latency_ms])
  #   StatsD.increment("ai_bouncer.#{classification[:label]}")
  # }

  # Headers to include in classification (for fingerprinting)
  config.include_headers = %w[User-Agent Content-Type Accept Accept-Language]

  # Maximum request body size to analyze (bytes)
  config.max_body_size = 10_000
end

# =============================================================================
# Controller Usage (alternative to middleware)
# =============================================================================
#
# For more control, use the controller concern instead of/alongside middleware:
#
#   class SessionsController < ApplicationController
#     include AiBouncer::ControllerConcern
#
#     # Option 1: Protect specific actions with custom options
#     protect_from_attacks only: [:create], threshold: 0.5, action: :block
#
#     # Option 2: Manual check in action
#     def create
#       check_for_attack  # Will block/log based on config
#       # ... rest of action
#     end
#   end
#
# =============================================================================
