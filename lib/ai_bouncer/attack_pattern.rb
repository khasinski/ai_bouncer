# frozen_string_literal: true

module AiBouncer
  # ActiveRecord model for storing attack pattern vectors
  # Uses pgvector via the neighbor gem for fast similarity search
  #
  # Usage:
  #   # Find similar patterns
  #   embedding = AiBouncer.model.embed("POST /login username=admin' OR '1'='1")
  #   patterns = AiBouncer::AttackPattern.nearest_neighbors(:embedding, embedding, distance: "cosine").limit(5)
  #
  #   # Classify request
  #   result = AiBouncer::AttackPattern.classify(embedding, k: 5)
  #
  class AttackPattern < ActiveRecord::Base
    self.table_name = "attack_patterns"

    # Include neighbor for vector similarity search
    # Requires: gem "neighbor" in Gemfile
    if defined?(Neighbor)
      has_neighbors :embedding
    end

    ATTACK_LABELS = %w[sqli xss path_traversal command_injection credential_stuffing spam_bot scanner].freeze
    SEVERITIES = %w[low medium high critical].freeze

    validates :label, presence: true, inclusion: { in: ATTACK_LABELS + ["clean"] }
    validates :severity, inclusion: { in: SEVERITIES }, allow_nil: true
    validates :embedding, presence: true

    scope :attacks_only, -> { where.not(label: "clean") }
    scope :by_label, ->(label) { where(label: label) }
    scope :by_severity, ->(severity) { where(severity: severity) }

    # Classify an embedding using KNN voting
    # Returns hash with label, confidence, neighbors, etc.
    def self.classify(embedding, k: 5)
      unless defined?(Neighbor)
        raise AiBouncer::Error, "neighbor gem required for database classification. Add 'gem \"neighbor\"' to your Gemfile."
      end

      start_time = Process.clock_gettime(Process::CLOCK_MONOTONIC)

      # Find k nearest neighbors using cosine distance
      neighbors = nearest_neighbors(:embedding, embedding, distance: "cosine")
                  .limit(k)
                  .select(:id, :label, :severity, :sample_text)

      # Get distances (neighbor gem returns them via neighbor_distance)
      neighbor_data = neighbors.map do |n|
        {
          id: n.id,
          label: n.label,
          severity: n.severity,
          distance: n.neighbor_distance,
          similarity: 1.0 - n.neighbor_distance
        }
      end

      result = compute_result(neighbor_data)

      end_time = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      result[:latency_ms] = ((end_time - start_time) * 1000).round(2)
      result[:storage] = :database

      result
    end

    # Batch import embeddings from bundled data
    def self.seed_from_bundled_data!(model_path: nil)
      model_path ||= AiBouncer.configuration.model_path
      raise AiBouncer::ConfigurationError, "model_path not configured" unless model_path

      vectors_path = File.join(model_path, "vectors.bin")
      labels_path = File.join(model_path, "labels.json")

      unless File.exist?(vectors_path) && File.exist?(labels_path)
        raise AiBouncer::ModelNotFoundError, "Bundled data not found at #{model_path}"
      end

      # Load labels metadata
      labels_data = JSON.parse(File.read(labels_path))
      labels = labels_data["labels"]
      severities = labels_data["severities"]
      num_vectors = labels_data["num_vectors"]
      dim = labels_data["dim"]

      # Load vectors (binary float32)
      data = File.binread(vectors_path)
      floats = data.unpack("e*") # little-endian float32

      vectors = []
      floats.each_slice(dim) { |row| vectors << row }

      # Clear existing data
      delete_all

      # Batch insert
      records = vectors.each_with_index.map do |vec, i|
        {
          label: labels[i],
          severity: severities[i],
          embedding: vec,
          source: "bundled",
          created_at: Time.current,
          updated_at: Time.current
        }
      end

      # Insert in batches of 500
      records.each_slice(500) do |batch|
        insert_all(batch)
      end

      count
    end

    private

    def self.compute_result(neighbors)
      return { label: "clean", confidence: 0.0, is_attack: false } if neighbors.empty?

      # Vote on label with distance weighting
      votes = Hash.new(0.0)

      neighbors.each do |n|
        weight = n[:similarity]
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
