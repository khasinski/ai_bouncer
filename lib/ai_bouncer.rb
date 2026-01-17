# frozen_string_literal: true

require "json"
require "onnxruntime"

require_relative "ai_bouncer/version"
require_relative "ai_bouncer/configuration"
require_relative "ai_bouncer/downloader"
require_relative "ai_bouncer/model"
require_relative "ai_bouncer/classifier"
require_relative "ai_bouncer/middleware"

# Rails-specific components loaded conditionally
if defined?(ActiveSupport::Concern)
  require_relative "ai_bouncer/controller_concern"
end

module AiBouncer
  class Error < StandardError; end
  class ModelNotFoundError < Error; end
  class ConfigurationError < Error; end

  class << self
    attr_writer :configuration

    def configuration
      @configuration ||= Configuration.new
    end

    alias config configuration

    def configure
      yield(configuration)
      validate_configuration!

      if configuration.enabled && configuration.memory_storage? && configuration.model_path
        load_classifier if configuration.preload_model
      end
    end

    # The ONNX embedding model (shared between memory and database modes)
    def model
      @model ||= load_model
    end

    # The in-memory classifier (only for memory storage mode)
    def classifier
      @classifier ||= load_classifier
    end

    def enabled?
      return false unless configuration.enabled

      if configuration.database_storage?
        defined?(AttackPattern) && AttackPattern.any?
      else
        !!(@classifier || configuration.model_path)
      end
    end

    # Classify a request text
    # Automatically uses the configured storage mode
    def classify(request_text, k: 5)
      if configuration.database_storage?
        classify_with_database(request_text, k: k)
      else
        classifier.classify(request_text, k: k)
      end
    end

    # Helper to build request text from components
    def request_to_text(**args)
      Classifier.request_to_text(**args)
    end

    def reset!
      @configuration = nil
      @classifier = nil
      @model = nil
    end

    private

    def classify_with_database(request_text, k: 5)
      require_relative "ai_bouncer/attack_pattern"

      embedding = model.embed(request_text)
      AttackPattern.classify(embedding, k: k)
    end

    def load_model
      return nil unless configuration.model_path

      model_path = configuration.model_path.to_s
      ensure_model_files!(model_path)

      Model.new(model_path)
    end

    def load_classifier
      return nil unless configuration.model_path

      model_path = configuration.model_path.to_s
      ensure_model_files!(model_path)

      @classifier = Classifier.new(model_path)
    end

    def ensure_model_files!(model_path)
      # Check if model exists
      if Downloader.model_exists?(model_path)
        return true
      end

      # Auto-download if enabled
      if configuration.auto_download
        Downloader.ensure_model!(
          model_path,
          verbose: configuration.verbose_download
        )
        return true
      end

      # No auto-download, check what's missing and raise helpful error
      unless File.directory?(model_path)
        raise ModelNotFoundError,
              "Model directory not found: #{model_path}\n" \
              "Run: rails generate ai_bouncer:install\n" \
              "Or set config.auto_download = true"
      end

      required_files = Downloader::REQUIRED_FILES
      missing_files = required_files.reject { |f| File.exist?(File.join(model_path, f)) }

      if missing_files.any?
        raise ModelNotFoundError,
              "Missing model files: #{missing_files.join(', ')}\n" \
              "Run: rails generate ai_bouncer:install\n" \
              "Or set config.auto_download = true"
      end
    end

    def validate_configuration!
      if configuration.protected_paths.empty? && configuration.enabled
        warn "[AiBouncer] Warning: No protected paths configured"
      end

      if configuration.threshold < 0 || configuration.threshold > 1
        raise ConfigurationError, "Threshold must be between 0 and 1"
      end

      if configuration.database_storage? && !defined?(Neighbor)
        warn "[AiBouncer] Warning: database storage requires the 'neighbor' gem"
      end
    end
  end
end

# Rails integration
require_relative "ai_bouncer/railtie" if defined?(Rails::Railtie)
