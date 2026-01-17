# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.9.0] - 2025-01-17

### Added

- **Core Classification Engine**
  - Model2Vec-based text embeddings via ONNX Runtime
  - KNN classifier with cosine similarity for attack detection
  - Support for 8 attack types: SQLi, XSS, path traversal, command injection, credential stuffing, spam bots, scanners, and clean traffic

- **Rails Integration**
  - Rack middleware for automatic request classification
  - Controller concern with `protect_from_attacks` DSL
  - Configurable actions: `:block`, `:log`, `:challenge`
  - Callbacks for attack detection and monitoring

- **Storage Options**
  - In-memory mode (default): ~2ms latency, ~30MB RAM
  - Database mode: PostgreSQL + pgvector via neighbor gem

- **Auto-Download**
  - Model files automatically downloaded from HuggingFace on first use
  - Hosted at [huggingface.co/khasinski/ai-bouncer](https://huggingface.co/khasinski/ai-bouncer)

- **Generators**
  - `rails generate ai_bouncer:install` - Creates initializer
  - `rails generate ai_bouncer:migration` - Creates pgvector migration

- **Rake Tasks**
  - `ai_bouncer:download` - Download model files
  - `ai_bouncer:seed` - Seed database with attack patterns
  - `ai_bouncer:stats` - Show pattern statistics
  - `ai_bouncer:test` - Test classification
  - `ai_bouncer:benchmark` - Benchmark performance

### Model

- 3,053 attack pattern vectors
- Trained on SecLists, CSIC 2010, ModSecurity CRS, and real nginx logs
- 92%+ accuracy on test set

## [Unreleased]

### Planned

- Rate limiting integration
- IP reputation scoring
- Custom pattern training interface
- Prometheus metrics export
