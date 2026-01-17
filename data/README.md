---
license: mit
language:
- en
tags:
- security
- waf
- web-application-firewall
- attack-detection
- sql-injection
- xss
- model2vec
- onnx
library_name: onnx
pipeline_tag: text-classification
---

# AiBouncer - HTTP Request Attack Classifier

A lightweight ML model for detecting malicious HTTP requests in web applications. Built for the [ai_bouncer](https://github.com/khasinski/ai_bouncer) Ruby gem.

## Model Details

- **Architecture**: Model2Vec (distilled from MiniLM)
- **Format**: ONNX for cross-platform inference
- **Size**: ~33MB total
- **Inference**: ~2ms per request
- **Embedding Dimension**: 256

## Attack Types Detected

| Label | Description | Severity |
|-------|-------------|----------|
| `sqli` | SQL Injection | High |
| `xss` | Cross-Site Scripting | High |
| `path_traversal` | Directory Traversal | High |
| `command_injection` | OS Command Injection | Critical |
| `credential_stuffing` | Automated Login Attempts | High |
| `spam_bot` | Comment/Form Spam | Medium |
| `scanner` | Vulnerability Scanning | Medium |
| `clean` | Legitimate Request | - |

## Files

| File | Size | Description |
|------|------|-------------|
| `embedding_model.onnx` | 29 MB | Model2Vec ONNX model |
| `vocab.json` | 552 KB | Tokenizer vocabulary (29k tokens) |
| `tokenizer_config.json` | 195 B | Tokenizer settings |
| `config.json` | 99 B | Model configuration |
| `vectors.bin` | 3 MB | Pre-computed attack pattern embeddings |
| `labels.json` | 94 KB | Labels and metadata for vectors |

## Usage with Ruby

```ruby
# Gemfile
gem 'ai_bouncer'

# config/initializers/ai_bouncer.rb
AiBouncer.configure do |config|
  config.enabled = true
  config.auto_download = true  # Downloads from HuggingFace automatically
end
```

## Training Data

The model's vector database was built from:
- **SecLists/fuzzdb** - Security payload collections
- **CSIC 2010** - HTTP attack dataset
- **ModSecurity CRS** - Rule patterns
- **Real nginx logs** - Credential stuffing, spam bots, scanners

Total: 3,053 labeled attack patterns

## Performance

| Metric | Value |
|--------|-------|
| Accuracy | 92%+ |
| Mean Latency | 2ms |
| P99 Latency | 3ms |
| Memory Usage | ~30MB |

## Contributing Training Data

This model uses a relatively small dataset (~3,000 patterns). **Help make it better!**

If you have access to real-world traffic data:
- Attack logs (WAF blocks, failed logins, spam)
- Clean traffic (normal API requests)
- False positives (incorrectly flagged requests)

Please consider contributing anonymized samples. Open an issue at [github.com/khasinski/ai_bouncer](https://github.com/khasinski/ai_bouncer/issues).

## License

MIT License

## Citation

```bibtex
@software{ai_bouncer,
  author = {Hasinski, Chris},
  title = {AiBouncer: ML-powered HTTP Attack Detection for Rails},
  url = {https://github.com/khasinski/ai_bouncer},
  year = {2025}
}
```
