# frozen_string_literal: true

namespace :ai_bouncer do
  desc "Download model files from HuggingFace"
  task download: :environment do
    model_path = AiBouncer.configuration.model_path
    unless model_path
      abort "Error: model_path not configured. Set AiBouncer.config.model_path in your initializer."
    end

    if AiBouncer::Downloader.model_exists?(model_path)
      puts "Model already exists at #{model_path}"
      puts "To re-download, delete the directory first: rm -rf #{model_path}"
    else
      puts "Downloading model to #{model_path}..."
      AiBouncer::Downloader.download!(model_path, verbose: true)
      puts "Done!"
    end
  end

  desc "Seed attack patterns from bundled embeddings into the database"
  task seed: :environment do
    require "ai_bouncer/attack_pattern"

    puts "Seeding attack patterns from bundled data..."

    model_path = AiBouncer.configuration.model_path
    unless model_path
      abort "Error: model_path not configured. Set AiBouncer.config.model_path in your initializer."
    end

    count = AiBouncer::AttackPattern.seed_from_bundled_data!(model_path: model_path)
    puts "Seeded #{count} attack patterns."
  end

  desc "Show attack pattern statistics"
  task stats: :environment do
    require "ai_bouncer/attack_pattern"

    puts "Attack Pattern Statistics"
    puts "=" * 40

    total = AiBouncer::AttackPattern.count
    puts "Total patterns: #{total}"
    puts ""

    puts "By label:"
    AiBouncer::AttackPattern.group(:label).count.sort.each do |label, count|
      puts "  #{label}: #{count}"
    end
    puts ""

    puts "By severity:"
    AiBouncer::AttackPattern.group(:severity).count.sort.each do |severity, count|
      puts "  #{severity || 'nil'}: #{count}"
    end
  end

  desc "Test classification with sample inputs"
  task test: :environment do
    test_cases = [
      { text: "POST /login username=admin password=secret123", expected: "clean" },
      { text: "POST /login username=admin' OR '1'='1", expected: "sqli" },
      { text: "POST /comment body=<script>alert('xss')</script>", expected: "xss" },
      { text: "GET /files?path=../../../etc/passwd", expected: "path_traversal" },
      { text: "GET /ping?host=;cat /etc/passwd", expected: "command_injection" }
    ]

    puts "Testing AiBouncer classification..."
    puts "Storage mode: #{AiBouncer.configuration.storage}"
    puts "=" * 60

    correct = 0
    test_cases.each do |tc|
      result = AiBouncer.classify(tc[:text])
      match = result[:label] == tc[:expected]
      correct += 1 if match

      status = match ? "✓" : "✗"
      puts "#{status} Expected: #{tc[:expected]}, Got: #{result[:label]} (#{(result[:confidence] * 100).round(1)}%)"
      puts "  Input: #{tc[:text][0, 50]}..."
      puts ""
    end

    puts "=" * 60
    puts "Accuracy: #{correct}/#{test_cases.size} (#{(correct.to_f / test_cases.size * 100).round(1)}%)"
  end

  desc "Benchmark classification performance"
  task benchmark: :environment do
    require "benchmark"

    sample_texts = [
      "POST /login username=john password=secret123",
      "GET /api/users/123",
      "POST /login username=admin' OR '1'='1",
      "POST /comment body=<script>alert('xss')</script>",
      "GET /files?path=../../../etc/passwd"
    ]

    puts "Benchmarking AiBouncer classification..."
    puts "Storage mode: #{AiBouncer.configuration.storage}"
    puts "=" * 60

    # Warmup
    3.times { AiBouncer.classify(sample_texts.first) }

    iterations = 100
    times = []

    iterations.times do
      text = sample_texts.sample
      start = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      AiBouncer.classify(text)
      elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - start
      times << elapsed * 1000 # Convert to ms
    end

    avg = times.sum / times.size
    min = times.min
    max = times.max
    p50 = times.sort[times.size / 2]
    p99 = times.sort[(times.size * 0.99).to_i]

    puts "Results (#{iterations} iterations):"
    puts "  Average: #{avg.round(2)} ms"
    puts "  Min:     #{min.round(2)} ms"
    puts "  Max:     #{max.round(2)} ms"
    puts "  P50:     #{p50.round(2)} ms"
    puts "  P99:     #{p99.round(2)} ms"
  end
end
