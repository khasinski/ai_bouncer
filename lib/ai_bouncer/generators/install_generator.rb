# frozen_string_literal: true

require "rails/generators/base"

module AiBouncer
  module Generators
    class InstallGenerator < Rails::Generators::Base
      source_root File.expand_path("templates", __dir__)

      desc "Creates an AiBouncer initializer and copies model files"

      def copy_initializer
        template "ai_bouncer.rb", "config/initializers/ai_bouncer.rb"
      end

      def copy_model_files
        # Check if model files exist in gem
        gem_data_path = File.expand_path("../../../../data", __dir__)

        if Dir.exist?(gem_data_path) && Dir.children(gem_data_path).any?
          directory gem_data_path, "vendor/ai_bouncer"
          say "Model files copied to vendor/ai_bouncer", :green
        else
          say "Model files not found in gem. Please download them manually:", :yellow
          say "  1. Download from: https://github.com/khasinski/ai_bouncer/releases"
          say "  2. Extract to: vendor/ai_bouncer/"
          say "  Required files: embeddings.bin, vocab.json, vectors.bin, labels.json, config.json"
        end
      end

      def show_readme
        readme "README" if behavior == :invoke
      end
    end
  end
end
