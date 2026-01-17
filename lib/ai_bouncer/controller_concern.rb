# frozen_string_literal: true

module AiBouncer
  # Controller concern for protecting specific actions from malicious requests
  #
  # Usage in a controller:
  #
  #   class SessionsController < ApplicationController
  #     include AiBouncer::ControllerConcern
  #
  #     # Protect all actions
  #     before_action :check_for_attack
  #
  #     # Or protect specific actions
  #     before_action :check_for_attack, only: [:create, :update]
  #
  #     # Or use the class method for more control
  #     protect_from_attacks only: [:create], threshold: 0.5, action: :block
  #   end
  #
  module ControllerConcern
    extend ActiveSupport::Concern

    included do
      class_attribute :ai_bouncer_options, default: {}
    end

    class_methods do
      # Declarative way to protect actions
      #
      # Options:
      #   :only     - Only protect these actions
      #   :except   - Protect all except these actions
      #   :threshold - Override default confidence threshold (0.0-1.0)
      #   :action   - What to do on attack (:block, :log, :challenge)
      #   :if       - Proc that returns true if check should run
      #   :unless   - Proc that returns true if check should be skipped
      #
      def protect_from_attacks(**options)
        self.ai_bouncer_options = options

        before_action_options = options.slice(:only, :except, :if, :unless)
        before_action :check_for_attack, **before_action_options
      end
    end

    # Check the current request for attacks
    # Can be called manually or via before_action
    def check_for_attack
      return unless AiBouncer.enabled?

      result = classify_current_request
      return unless result[:is_attack]

      threshold = ai_bouncer_options[:threshold] || AiBouncer.configuration.threshold
      return if result[:confidence] < threshold

      handle_attack(result)
    end

    private

    def classify_current_request
      request_text = build_request_text
      AiBouncer.classify(request_text)
    end

    def build_request_text
      AiBouncer::Classifier.request_to_text(
        method: request.request_method,
        path: request.path,
        body: request_body_for_classification,
        user_agent: request.user_agent,
        params: filtered_params_for_classification,
        headers: headers_for_classification
      )
    end

    def request_body_for_classification
      return "" unless request.post? || request.put? || request.patch?

      max_size = AiBouncer.configuration.max_body_size
      body = request.body.read(max_size)
      request.body.rewind
      body.to_s
    end

    def filtered_params_for_classification
      # Exclude Rails internal params and sensitive data
      excluded = %w[controller action format authenticity_token password password_confirmation]
      request.params.except(*excluded)
    end

    def headers_for_classification
      include_headers = AiBouncer.configuration.include_headers
      include_headers.each_with_object({}) do |header, hash|
        key = "HTTP_#{header.upcase.tr('-', '_')}"
        hash[header] = request.env[key] if request.env[key]
      end
    end

    def handle_attack(result)
      action = ai_bouncer_options[:action] || AiBouncer.configuration.action

      # Log the attack
      log_attack(result)

      # Call callback if configured
      if AiBouncer.configuration.on_attack_detected
        AiBouncer.configuration.on_attack_detected.call(
          request: request,
          classification: result,
          action: action
        )
      end

      case action
      when :block
        block_request(result)
      when :challenge
        challenge_request(result)
      when :log
        # Just log, don't block
        nil
      end
    end

    def log_attack(result)
      logger = AiBouncer.configuration.logger || Rails.logger

      message = "[AiBouncer] Attack detected: #{result[:label]} " \
                "(confidence: #{(result[:confidence] * 100).round(1)}%) " \
                "path: #{request.path} ip: #{request.remote_ip}"

      case result[:label]
      when "sqli", "command_injection", "path_traversal"
        logger.error(message)
      when "xss"
        logger.warn(message)
      else
        logger.info(message)
      end
    end

    def block_request(result)
      response_config = AiBouncer.configuration.block_response

      respond_to do |format|
        format.html do
          render plain: response_config[:body],
                 status: response_config[:status]
        end
        format.json do
          render json: {
            error: "Forbidden",
            code: "attack_detected",
            label: result[:label]
          }, status: response_config[:status]
        end
        format.any do
          head response_config[:status]
        end
      end
    end

    def challenge_request(result)
      response_config = AiBouncer.configuration.challenge_response

      # Store classification result for potential CAPTCHA page
      session[:ai_bouncer_challenge] = {
        label: result[:label],
        confidence: result[:confidence],
        path: request.path,
        challenged_at: Time.current
      }

      respond_to do |format|
        format.html do
          if response_config[:redirect_to]
            redirect_to response_config[:redirect_to]
          else
            render plain: response_config[:body],
                   status: response_config[:status]
          end
        end
        format.json do
          render json: {
            error: "Challenge required",
            code: "challenge_required"
          }, status: response_config[:status]
        end
        format.any do
          head response_config[:status]
        end
      end
    end
  end
end
