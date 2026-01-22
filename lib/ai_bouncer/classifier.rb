# frozen_string_literal: true

require "json"
require "cgi"

module AiBouncer
  # HTTP request classifier using KNN on pre-computed attack vectors
  class Classifier
    ATTACK_LABELS = %w[
      sqli xss path_traversal command_injection credential_stuffing spam_bot
      scanner ssrf xxe nosql_injection ssti log4shell open_redirect ldap_injection
    ].freeze

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
        ua_type = if %w[sqlmap nikto zgrab nmap wpscan dirbuster gobuster nuclei acunetix burp].any? { |s| ua_lower.include?(s) }
                    "scanner"
                  elsif %w[bot crawler curl python java wget go-http libwww perl mechanize axios node-fetch ruby].any? { |b| ua_lower.include?(b) }
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
        headers.each do |name, value|
          next if value.nil? || value.empty?
          name_lower = name.to_s.downcase
          parts << "HAS_REFERER" if name_lower == "referer" || name_lower == "referrer"
          parts << "HAS_XML_CONTENT" if name_lower == "content-type" && value.to_s.include?("xml")
          parts << "HAS_JSON_CONTENT" if name_lower == "content-type" && value.to_s.include?("json")
        end
      end

      # Combine all text for pattern analysis
      header_values = headers.values.compact.join(" ")
      combined = "#{path} #{body} #{params.values.join(' ')} #{header_values}"

      # URL-decode combined text for better pattern detection
      decoded_combined = begin
        CGI.unescape(combined)
      rescue StandardError
        combined
      end

      # ============ Advanced Feature Extraction ============

      # Entropy calculation (high entropy often indicates encoded attacks)
      entropy = calculate_entropy(combined)
      parts << "ENTROPY:#{entropy_bucket(entropy)}"

      # URL encoding detection
      encoding_depth = detect_encoding_depth(combined)
      parts << "ENCODING:#{encoding_depth}" if encoding_depth > 0

      # Special character density (use decoded for accuracy)
      special_density = special_char_density(decoded_combined)
      parts << "SPECIAL_DENSITY:#{density_bucket(special_density)}"

      # ============ Attack Pattern Flags (use decoded_combined for detection) ============

      # SQL Injection patterns
      if decoded_combined =~ /\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|OR\s+\d|AND\s+\d|--|'|;|\bWHERE\b|\bFROM\b|\bSLEEP\s*\(|WAITFOR|BENCHMARK|PG_SLEEP|EXTRACTVALUE|UPDATEXML)/i
        parts << "FLAG:SQL_KEYWORDS"
      end

      # XSS patterns
      if decoded_combined =~ /(<script|javascript:|onerror|onload|onmouseover|onfocus|onclick|alert\s*\(|prompt\s*\(|confirm\s*\(|<svg|<img[^>]+on\w+=|<iframe|<body[^>]+on\w+=|expression\s*\(|eval\s*\()/i
        parts << "FLAG:XSS_PATTERN"
      end

      # Path traversal
      if decoded_combined =~ /(\.\.[\/\\])/i
        parts << "FLAG:PATH_TRAVERSAL"
      end

      # Command injection
      if decoded_combined =~ /(\||;|`|\$\(|&&|\|\||>\s*\/|<\s*\/|\bcat\b|\bls\b|\bwhoami\b|\bid\b|\bping\b|\bnc\b|\bcurl\b|\bwget\b)/i
        parts << "FLAG:CMD_INJECTION"
      end

      # SSRF patterns
      if decoded_combined =~ /(169\.254\.169\.254|metadata\.google|127\.0\.0\.1|localhost|0\.0\.0\.0|\[::1\]|file:\/\/|gopher:\/\/|dict:\/\/|internal|\.internal)/i
        parts << "FLAG:SSRF_PATTERN"
      end

      # XXE patterns
      if decoded_combined =~ /(<!DOCTYPE|<!ENTITY|SYSTEM\s*["']|PUBLIC\s*["']|%xxe|&xxe)/i
        parts << "FLAG:XXE_PATTERN"
      end

      # NoSQL injection patterns (must have $ operator, not just JSON)
      if decoded_combined =~ /(\$gt|\$ne|\$lt|\$or|\$and|\$where|\$regex|\$exists|\$in|\$nin)["\s:}\]]/i
        parts << "FLAG:NOSQL_PATTERN"
      end

      # SSTI patterns
      if decoded_combined =~ /(\{\{.*\}\}|\$\{.*\}|<%.*%>|\#\{.*\}|__class__|__mro__|__subclasses__|__globals__|__builtins__|config\.|request\.|self\.)/i
        parts << "FLAG:SSTI_PATTERN"
      end

      # Log4Shell patterns
      if decoded_combined =~ /(\$\{jndi:|j\$\{|jn\$\{|\$\{lower:j\}|\$\{upper:j\}|ldap:\/\/|rmi:\/\/)/i
        parts << "FLAG:LOG4SHELL_PATTERN"
      end

      # Open redirect patterns
      if decoded_combined =~ /(redirect|return|next|url|goto|dest|continue|rurl)=.*?(https?:\/\/|\/\/)[^\/]/i
        parts << "FLAG:REDIRECT_PATTERN"
      end

      # LDAP injection patterns
      if decoded_combined =~ /(\*\)\(|\)\(|objectClass|\)\(&\)|\)\(\|)/i
        parts << "FLAG:LDAP_PATTERN"
      end

      # Scanner fingerprints in paths
      if path =~ /(\.env|\.git|wp-config|phpinfo|\.aws|backup\.sql|\.htpasswd|web\.config|actuator|swagger|api-docs)/i
        parts << "FLAG:SCANNER_PATH"
      end

      # ============ Payload ============
      payload_parts = []
      payload_parts << body.to_s unless body.to_s.empty?
      payload_parts << params.to_s unless params.empty?
      # Include Referer if present (common attack vector)
      referer = headers["Referer"] || headers["referer"]
      payload_parts << "REFERER:#{referer}" if referer && !referer.empty?
      payload = payload_parts.join(" ")
      parts << "PAYLOAD:#{payload[0, 500]}" unless payload.empty?

      parts.join(" ")
    end

    # Calculate Shannon entropy of a string
    def self.calculate_entropy(str)
      return 0.0 if str.nil? || str.empty?

      freq = Hash.new(0)
      str.each_char { |c| freq[c] += 1 }

      len = str.length.to_f
      entropy = 0.0
      freq.each_value do |count|
        prob = count / len
        entropy -= prob * Math.log2(prob) if prob > 0
      end
      entropy
    end

    def self.entropy_bucket(entropy)
      case entropy
      when 0..2.5 then "low"
      when 2.5..4.0 then "normal"
      when 4.0..5.5 then "high"
      else "very_high"
      end
    end

    # Detect URL encoding depth (double/triple encoding)
    def self.detect_encoding_depth(str)
      return 0 if str.nil? || str.empty?

      depth = 0
      current = str
      3.times do
        decoded = begin
          CGI.unescape(current)
        rescue StandardError
          current
        end
        break if decoded == current

        depth += 1
        current = decoded
      end
      depth
    end

    # Calculate special character density
    def self.special_char_density(str)
      return 0.0 if str.nil? || str.empty?

      special_chars = str.count("'\"<>(){}[];|&$`\\!@#%^*=+~")
      special_chars.to_f / str.length
    end

    def self.density_bucket(density)
      case density
      when 0..0.05 then "low"
      when 0.05..0.15 then "normal"
      when 0.15..0.3 then "high"
      else "very_high"
      end
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
