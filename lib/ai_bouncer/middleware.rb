# frozen_string_literal: true

module AiBouncer
  # Rack middleware for HTTP request classification
  # Integrates with Rails or any Rack-based application
  class Middleware
    def initialize(app)
      @app = app
    end

    def call(env)
      return @app.call(env) unless AiBouncer.enabled?

      request = Rack::Request.new(env)

      # Check if this path should be protected
      unless AiBouncer.config.protected_path?(request.path)
        return @app.call(env)
      end

      # Classify the request
      classification = classify_request(request)

      # Store classification in env for controllers to access
      env["ai_bouncer.classification"] = classification

      # Call callback if configured
      AiBouncer.config.on_classification&.call(
        request: request,
        classification: classification
      )

      # Handle attack detection
      if classification[:is_attack] && classification[:confidence] >= AiBouncer.config.threshold
        return handle_attack(request, classification, env)
      end

      @app.call(env)
    end

    private

    def classify_request(request)
      # Build text representation
      request_text = Classifier.request_to_text(
        method: request.request_method,
        path: request.path,
        body: read_body(request),
        user_agent: request.user_agent,
        params: request.params,
        headers: extract_headers(request)
      )

      # Classify
      AiBouncer.classifier.classify(request_text)
    end

    def read_body(request)
      return "" unless request.post? || request.put? || request.patch?

      body = request.body.read
      request.body.rewind

      # Truncate if too large
      max_size = AiBouncer.config.max_body_size
      body.length > max_size ? body[0, max_size] : body
    rescue StandardError
      ""
    end

    def extract_headers(request)
      headers = {}
      AiBouncer.config.include_headers.each do |header|
        key = "HTTP_#{header.upcase.tr('-', '_')}"
        headers[header] = request.env[key] if request.env[key]
      end
      headers
    end

    def handle_attack(request, classification, env)
      # Log the attack
      log_attack(request, classification)

      # Call callback
      AiBouncer.config.on_attack_detected&.call(
        request: request,
        classification: classification,
        action: AiBouncer.config.action
      )

      case AiBouncer.config.action
      when :block
        block_response(classification)
      when :challenge
        challenge_response(classification)
      when :log
        # Just log, continue with request
        @app.call(env)
      else
        @app.call(env)
      end
    end

    def block_response(classification)
      response = AiBouncer.config.block_response

      body = if response[:body].is_a?(Proc)
               response[:body].call(classification)
             else
               response[:body]
             end

      headers = response[:headers] || { "Content-Type" => "text/plain" }

      [response[:status] || 403, headers, [body]]
    end

    def challenge_response(classification)
      response = AiBouncer.config.challenge_response

      body = if response[:body].is_a?(Proc)
               response[:body].call(classification)
             else
               response[:body]
             end

      headers = response[:headers] || { "Content-Type" => "text/plain" }

      [response[:status] || 429, headers, [body]]
    end

    def log_attack(request, classification)
      logger = AiBouncer.config.logger || (defined?(Rails) ? Rails.logger : nil)
      return unless logger

      logger.warn(
        "[AiBouncer] Attack detected: " \
        "label=#{classification[:label]} " \
        "confidence=#{classification[:confidence]} " \
        "path=#{request.path} " \
        "method=#{request.request_method} " \
        "ip=#{request.ip} " \
        "latency_ms=#{classification[:latency_ms]}"
      )
    end
  end
end
