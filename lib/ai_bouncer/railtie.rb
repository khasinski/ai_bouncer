# frozen_string_literal: true

module AiBouncer
  class Railtie < Rails::Railtie
    initializer "ai_bouncer.configure_rails_initialization" do |app|
      # Insert middleware early in the stack (after Rack::Runtime)
      app.middleware.insert_after Rack::Runtime, AiBouncer::Middleware
    end

    # Load controller concern for ActionController
    initializer "ai_bouncer.controller_concern" do
      ActiveSupport.on_load(:action_controller) do
        require "ai_bouncer/controller_concern"
      end
    end

    # Load rake tasks
    rake_tasks do
      load File.expand_path("tasks/ai_bouncer.rake", __dir__)
    end

    # Provide generators
    generators do
      require_relative "generators/install_generator"
      require_relative "generators/migration_generator"
    end

    # Load AttackPattern model if using database storage and ActiveRecord is available
    initializer "ai_bouncer.load_attack_pattern", after: :load_active_record do
      ActiveSupport.on_load(:active_record) do
        if AiBouncer.configuration.database_storage?
          require "ai_bouncer/attack_pattern"
        end
      end
    end
  end
end
