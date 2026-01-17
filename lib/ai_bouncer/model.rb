# frozen_string_literal: true

require "json"

module AiBouncer
  # ONNX-based embedding model using Model2Vec
  # Implements Unigram tokenization compatible with HuggingFace tokenizers
  class Model
    attr_reader :embedding_dim

    # Punctuation characters to space-pad (matching BertNormalizer)
    PUNCTUATION = '!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'.freeze

    def initialize(model_path)
      @model_path = model_path
      load_model
    end

    # Compute embedding for text
    # Returns normalized float array
    def embed(text)
      token_ids, attention_mask = tokenize(text)
      run_inference(token_ids, attention_mask)
    end

    private

    def load_model
      # Load ONNX model (model2vec.onnx)
      onnx_path = File.join(@model_path, "embedding_model.onnx")
      unless File.exist?(onnx_path)
        raise ModelNotFoundError, "ONNX model not found: #{onnx_path}"
      end

      @session = OnnxRuntime::Model.new(onnx_path)

      # Load tokenizer config
      config_path = File.join(@model_path, "tokenizer_config.json")
      @tokenizer_config = JSON.parse(File.read(config_path))
      @max_length = @tokenizer_config["max_length"] || 128
      @pad_token_id = @tokenizer_config["pad_token_id"] || 0
      @unk_token_id = @tokenizer_config["unk_token_id"] || 1
      @metaspace = @tokenizer_config["metaspace_replacement"] || "▁"

      # Load vocabulary (token -> id mapping)
      vocab_path = File.join(@model_path, "vocab.json")
      @vocab = JSON.parse(File.read(vocab_path))

      # Build Trie for fast longest-prefix matching
      @trie = build_trie(@vocab)

      # Get embedding dim from model config
      model_config_path = File.join(@model_path, "config.json")
      if File.exist?(model_config_path)
        model_config = JSON.parse(File.read(model_config_path))
        @embedding_dim = model_config["embedding_dim"] || 256
      else
        @embedding_dim = 256
      end
    end

    def tokenize(text)
      # Step 1: Normalize (lowercase, space-pad punctuation)
      normalized = normalize_text(text)

      # Step 2: Apply Metaspace pre-tokenization
      # Add ▁ at the beginning and before each word
      words = normalized.split(/\s+/).reject(&:empty?)
      metaspace_text = words.map { |w| "#{@metaspace}#{w}" }.join

      # Step 3: Unigram tokenization (greedy longest match)
      token_ids = unigram_tokenize(metaspace_text)

      # Truncate to max_length
      token_ids = token_ids[0, @max_length] if token_ids.size > @max_length

      attention_mask = Array.new(token_ids.size, 1)

      # Pad to max_length
      while token_ids.size < @max_length
        token_ids << @pad_token_id
        attention_mask << 0
      end

      [token_ids, attention_mask]
    end

    def normalize_text(text)
      # Lowercase
      result = text.downcase

      # Space-pad each punctuation character
      PUNCTUATION.each_char do |p|
        result = result.gsub(p, " #{p} ")
      end

      # Collapse multiple spaces and strip
      result.gsub(/\s+/, " ").strip
    end

    def build_trie(vocab)
      trie = {}
      vocab.each do |token, id|
        node = trie
        token.each_char do |char|
          node[char] ||= {}
          node = node[char]
        end
        node[:id] = id
        node[:token] = token
      end
      trie
    end

    def unigram_tokenize(text)
      tokens = []
      pos = 0

      while pos < text.length
        # Find longest matching token using Trie
        node = @trie
        best_id = nil
        best_len = 0
        match_len = 0

        # Traverse trie as far as possible
        (pos...text.length).each do |i|
          char = text[i]
          break unless node[char]

          node = node[char]
          match_len += 1

          # If this node has a token, record it
          if node[:id]
            best_id = node[:id]
            best_len = match_len
          end
        end

        if best_id
          tokens << best_id
          pos += best_len
        else
          # No match found, use UNK and skip one character
          tokens << @unk_token_id
          pos += 1
        end
      end

      tokens.empty? ? [@unk_token_id] : tokens
    end

    def run_inference(token_ids, attention_mask)
      # ONNX Runtime expects 2D arrays
      inputs = {
        "token_ids" => [token_ids],
        "attention_mask" => [attention_mask]
      }

      outputs = @session.predict(inputs)

      # Output is {"embedding" => [[...256 floats...]]}
      embedding = outputs["embedding"]&.first || outputs.values.first&.first

      raise "Failed to get embedding from model" unless embedding

      embedding
    end
  end
end
