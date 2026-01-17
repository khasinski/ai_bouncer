# frozen_string_literal: true

require "json"

module AiBouncer
  # HTTP request classifier using KNN on pre-computed attack vectors
  class Classifier
    ATTACK_LABELS = %w[sqli xss path_traversal command_injection credential_stuffing spam_bot].freeze

    attr_reader :model

    def initialize(model_path)
      @model_path = model_path
      @model = Model.new(model_path)
      load_vectors
    end

    # Classify an HTTP request
    # Returns classification result hash
    def classify(request_text, k: 5)
      start_time = Process.clock_gettime(Process::CLOCK_MONOTONIC)

      # Compute embedding
      embedding = @model.embed(request_text)

      # Find k nearest neighbors
      neighbors = knn_search(embedding, k)

      # Vote on label
      result = compute_result(neighbors)

      end_time = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      result[:latency_ms] = ((end_time - start_time) * 1000).round(2)

      result
    end

    # Convert HTTP request to text representation
    def self.request_to_text(method:, path:, body: "", user_agent: "", params: {}, headers: {})
      parts = []

      parts << "METHOD:#{method.upcase}"
      parts << "PATH:#{path}"

      # Path depth
      depth = path.count("/")
      parts << "DEPTH:#{depth}"

      # Params
      parts << "PARAMS:#{params.size}" if params.any?

      # User agent classification
      if user_agent && !user_agent.empty?
        ua_lower = user_agent.downcase
        ua_type = if %w[bot crawler curl python java wget].any? { |b| ua_lower.include?(b) }
                    "bot"
                  elsif %w[mozilla chrome safari firefox edge opera].any? { |b| ua_lower.include?(b) }
                    "browser"
                  else
                    "unknown"
                  end
        parts << "UA_TYPE:#{ua_type}"
      end

      # Body analysis
      if body && !body.empty?
        size_bucket = case body.length
                      when 0..99 then "tiny"
                      when 100..499 then "small"
                      when 500..1999 then "medium"
                      else "large"
                      end
        parts << "BODY_SIZE:#{size_bucket}"
      end

      # Header analysis
      if headers.any?
        parts << "HEADERS:#{headers.size}"
        # Include header values for pattern detection
        headers.each do |name, value|
          next if value.nil? || value.empty?
          # Flag suspicious header names
          if name.downcase == "referer" || name.downcase == "referrer"
            parts << "HAS_REFERER"
          end
        end
      end

      # Suspicious pattern detection - include headers in combined text
      header_values = headers.values.compact.join(' ')
      combined = "#{path} #{body} #{params.values.join(' ')} #{header_values}"

      if combined =~ /\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|OR\s+\d|--|')/i
        parts << "FLAG:SQL_KEYWORDS"
      end

      if combined =~ /(<script|javascript:|onerror|onload|alert\()/i
        parts << "FLAG:XSS_PATTERN"
      end

      if combined =~ /(\.\.|%2e%2e)/i
        parts << "FLAG:PATH_TRAVERSAL"
      end

      if combined =~ /(\||;|`|\$\(|&&|\|\|)/
        parts << "FLAG:CMD_INJECTION"
      end

      # Include payload snippet (body, params, and suspicious headers)
      payload_parts = []
      payload_parts << body.to_s unless body.to_s.empty?
      payload_parts << params.to_s unless params.empty?
      # Include Referer if present (common attack vector)
      if headers["Referer"] || headers["referer"]
        referer = headers["Referer"] || headers["referer"]
        payload_parts << "REFERER:#{referer}" unless referer.empty?
      end
      payload = payload_parts.join(" ")
      parts << "PAYLOAD:#{payload[0, 300]}" unless payload.empty?

      parts.join(" ")
    end

    private

    def load_vectors
      vectors_path = File.join(@model_path, "vectors.bin")
      labels_path = File.join(@model_path, "labels.json")

      # Load labels metadata
      labels_data = JSON.parse(File.read(labels_path))
      @labels = labels_data["labels"]
      @severities = labels_data["severities"]
      @num_vectors = labels_data["num_vectors"]
      @dim = labels_data["dim"]

      # Load vectors (binary float32)
      data = File.binread(vectors_path)
      floats = data.unpack("e*") # little-endian float32

      @vectors = []
      floats.each_slice(@dim) do |row|
        @vectors << row
      end
    end

    def knn_search(query_embedding, k)
      distances = []

      @vectors.each_with_index do |vec, i|
        # Cosine similarity -> distance
        similarity = cosine_similarity(query_embedding, vec)
        distance = 1.0 - similarity

        distances << {
          index: i,
          label: @labels[i],
          severity: @severities[i],
          distance: distance,
          similarity: similarity
        }
      end

      # Sort by distance (ascending)
      distances.sort_by { |d| d[:distance] }.first(k)
    end

    def cosine_similarity(a, b)
      dot = 0.0
      norm_a = 0.0
      norm_b = 0.0

      a.each_with_index do |val, i|
        dot += val * b[i]
        norm_a += val * val
        norm_b += b[i] * b[i]
      end

      norm = Math.sqrt(norm_a) * Math.sqrt(norm_b)
      return 0.0 if norm < 1e-8

      dot / norm
    end

    def compute_result(neighbors)
      # Vote on label with distance weighting
      votes = Hash.new(0.0)

      neighbors.each do |n|
        weight = 1.0 - n[:distance]
        votes[n[:label]] += weight
      end

      # Get winner
      predicted_label = votes.max_by { |_, v| v }&.first || "clean"

      # Compute confidence
      nearest_distance = neighbors.first[:distance]
      confidence = 1.0 - nearest_distance

      # Adjust by voting margin
      total_weight = votes.values.sum
      winner_weight = votes[predicted_label]
      voting_confidence = total_weight > 0 ? winner_weight / total_weight : 0

      final_confidence = (confidence + voting_confidence) / 2

      {
        label: predicted_label,
        confidence: final_confidence.round(4),
        is_attack: predicted_label != "clean",
        nearest_distance: nearest_distance.round(4),
        neighbors: neighbors.map { |n| { label: n[:label], distance: n[:distance].round(4) } },
        votes: votes.transform_values { |v| v.round(4) }
      }
    end
  end
end
