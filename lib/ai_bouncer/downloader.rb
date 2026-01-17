# frozen_string_literal: true

require "net/http"
require "uri"
require "fileutils"

module AiBouncer
  # Downloads model files from HuggingFace Hub
  class Downloader
    HF_REPO = "khasinski/ai-bouncer"
    HF_BASE_URL = "https://huggingface.co/#{HF_REPO}/resolve/main".freeze

    REQUIRED_FILES = %w[
      embedding_model.onnx
      vocab.json
      tokenizer_config.json
      config.json
      vectors.bin
      labels.json
    ].freeze

    class DownloadError < StandardError; end

    class << self
      # Check if all required model files exist
      def model_exists?(path)
        return false unless path && File.directory?(path)

        REQUIRED_FILES.all? { |f| File.exist?(File.join(path, f)) }
      end

      # Download model files to the specified path
      def download!(path, verbose: true)
        FileUtils.mkdir_p(path)

        log("Downloading AiBouncer model from HuggingFace...", verbose)
        log("Repository: #{HF_REPO}", verbose)
        log("Destination: #{path}", verbose)

        download_from_huggingface(path, verbose)

        # Verify all files exist
        missing = REQUIRED_FILES.reject { |f| File.exist?(File.join(path, f)) }
        if missing.any?
          raise DownloadError, "Download incomplete. Missing files: #{missing.join(', ')}"
        end

        log("Model download complete!", verbose)
        true
      end

      # Ensure model exists, downloading if necessary
      def ensure_model!(path, verbose: true)
        return true if model_exists?(path)

        log("Model not found at #{path}", verbose)
        download!(path, verbose: verbose)
      end

      private

      def download_from_huggingface(path, verbose)
        REQUIRED_FILES.each do |filename|
          dest_file = File.join(path, filename)
          next if File.exist?(dest_file)

          url = "#{HF_BASE_URL}/#{filename}"
          log("  Downloading #{filename}...", verbose)

          download_file(url, dest_file)
        end
      end

      def download_file(url, dest_path, max_redirects: 5)
        raise DownloadError, "Too many redirects" if max_redirects <= 0

        uri = URI.parse(url)

        raise DownloadError, "Invalid URL: #{url}" unless uri.host

        Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == "https") do |http|
          http.read_timeout = 300  # 5 minutes for large files
          http.open_timeout = 30

          request = Net::HTTP::Get.new(uri.request_uri)
          request["User-Agent"] = "AiBouncer/#{VERSION}"

          http.request(request) do |response|
            case response
            when Net::HTTPSuccess
              File.open(dest_path, "wb") do |file|
                response.read_body do |chunk|
                  file.write(chunk)
                end
              end
            when Net::HTTPRedirection
              new_url = response["location"]
              # Handle relative redirects
              new_uri = URI.parse(new_url)
              if new_uri.relative?
                new_url = URI.join("#{uri.scheme}://#{uri.host}:#{uri.port}", new_url).to_s
              end
              download_file(new_url, dest_path, max_redirects: max_redirects - 1)
            else
              raise DownloadError, "HTTP #{response.code}: #{response.message} for #{url}"
            end
          end
        end
      end

      def log(message, verbose)
        return unless verbose

        if defined?(Rails) && Rails.logger
          Rails.logger.info("[AiBouncer] #{message}")
        else
          warn("[AiBouncer] #{message}")
        end
      end
    end
  end
end
