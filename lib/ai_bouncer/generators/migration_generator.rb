# frozen_string_literal: true

require "rails/generators"
require "rails/generators/active_record"

module AiBouncer
  module Generators
    class MigrationGenerator < Rails::Generators::Base
      include Rails::Generators::Migration

      source_root File.expand_path("templates", __dir__)

      desc "Creates a migration for the attack_patterns table with pgvector"

      class_option :embedding_dim, type: :numeric, default: 256,
                   desc: "Embedding dimension (default: 256 for Model2Vec)"

      def self.next_migration_number(dirname)
        ActiveRecord::Generators::Base.next_migration_number(dirname)
      end

      def create_migration_file
        @embedding_dim = options[:embedding_dim]
        migration_template "create_attack_patterns.rb.tt",
                           "db/migrate/create_attack_patterns.rb"
      end

      def show_post_install_message
        say ""
        say "Migration created! Next steps:", :green
        say "  1. Run: rails db:migrate"
        say "  2. Seed attack patterns: rails ai_bouncer:seed"
        say ""
        say "Note: Requires PostgreSQL with pgvector extension installed.", :yellow
      end
    end
  end
end
