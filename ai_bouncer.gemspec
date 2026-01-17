# frozen_string_literal: true

require_relative "lib/ai_bouncer/version"

Gem::Specification.new do |spec|
  spec.name = "ai_bouncer"
  spec.version = AiBouncer::VERSION
  spec.authors = ["Chris Hasinski"]
  spec.email = ["krzysztof.hasinski@gmail.com"]

  spec.summary = "AI-powered HTTP request classification for Rails"
  spec.description = "Detect credential stuffing, SQL injection, XSS, and other attacks using ML embeddings. Lightweight (~30MB model) with ~2ms inference time."
  spec.homepage = "https://github.com/khasinski/ai_bouncer"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.1.0"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["changelog_uri"] = "#{spec.homepage}/blob/main/CHANGELOG.md"
  spec.metadata["documentation_uri"] = spec.homepage
  spec.metadata["rubygems_mfa_required"] = "true"

  spec.files = Dir.chdir(__dir__) do
    Dir["{lib}/**/*", "README.md", "LICENSE.txt", "CHANGELOG.md"].reject do |f|
      File.directory?(f)
    end
  end

  spec.require_paths = ["lib"]

  # Runtime dependencies
  spec.add_dependency "onnxruntime", "~> 0.10"  # ONNX Runtime for ML inference

  # Optional: for database-backed vector storage
  # spec.add_dependency "neighbor", "~> 0.5"  # pgvector integration

  # Development dependencies
  spec.add_development_dependency "rake", "~> 13.0"
  spec.add_development_dependency "rspec", "~> 3.0"
  spec.add_development_dependency "rubocop", "~> 1.0"
end
