require "json"
require "colorize"
require "http"
require "option_parser"

# Incremental is a CLI tool that allows you to smartly make incremental scans
# using the BrightSec API.
module Incremental
  VERSION = "0.2.4"

  BANNER = <<-BANNER

  #{"  ╔╗  ╔═╗ ╦ ╔═╗ ╦ ╦ ╔╦╗".colorize(:light_magenta)}
  #{"  ╠╩╗ ╠╦╝ ║ ║ ╦ ╠═╣  ║ ".colorize(:magenta)}
  #{"  ╚═╝ ╩╚═ ╩ ╚═╝ ╩ ╩  ╩ ".colorize(:light_magenta)}
  #{"  ━━━ Incremental Scanner v#{VERSION} ━━━".colorize(:light_cyan)}
  BANNER

  SPINNER_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

  class Spinner
    @running = false
    @fiber : Fiber? = nil
    @message : String

    def initialize(@message = "Working")
    end

    def start
      @running = true
      frame = 0
      @fiber = spawn do
        while @running
          print "\r  #{SPINNER_FRAMES[frame % SPINNER_FRAMES.size].colorize(:light_cyan)} #{@message}..."
          frame += 1
          sleep 80.milliseconds
        end
      end
    end

    def update(@message : String)
    end

    def stop(final_message : String? = nil)
      @running = false
      if msg = final_message
        print "\r  #{"✔".colorize(:green)} #{msg}#{" " * 20}\n"
      else
        print "\r#{" " * 60}\r"
      end
    end
  end

  def self.progress_bar(current : Int32, total : Int32, width : Int32 = 30) : String
    return "" if total == 0
    pct = (current.to_f / total * 100).to_i
    filled = (current.to_f / total * width).to_i
    empty = width - filled
    bar = "█" * filled + "░" * empty
    "#{bar.colorize(:light_cyan)} #{pct}% (#{current}/#{total})"
  end

  API_TESTS = [
    "amazon_s3_takeover",
    "bopla",
    "business_constraint_bypass",
    "date_manipulation",
    "file_upload",
    "full_path_disclosure",
    "graphql_introspection",
    "id_enumeration",
    "improper_asset_management",
    "jwt",
    "nosql",
    "osi",
    "lfi",
    "rfi",
    "sqli",
    "ssrf",
    "xxe",
    "open_cloud_storage",
    "open_database",
    "prompt_injection",
  ]

  STATIC_TESTS = [
    "cve_test",
    "open_cloud_storage",
    "open_database",
    "amazon_s3_takeover",
    "retire_js",
    "secret_tokens",
  ]

  POST_TESTS = [
    "csrf",
    "file_upload",
    "css_injection",
    "xss",
    "full_path_disclosure",
    "excessive_data_exposure",
    "html_injection",
    "unvalidated_redirect",
    "lfi",
    "rfi",
    "sqli",
    "ssrf",
    "ssti",
    "osi",
    "proto_pollution",
    "server_side_js_injection",
    "nosql",
  ]

  HTML_TESTS = [
    "xss",
    "full_path_disclosure",
    "excessive_data_exposure",
    "html_injection",
    "unvalidated_redirect",
    "proto_pollution",
    "server_side_js_injection",
    "header_security",
    "cookie_security",
    "css_injection",
    "directory_listing",
    "secret_tokens",
    "insecure_output_handling",
  ]

  XML_TESTS = [
    "xxe",
    "xss",
    "secret_tokens",
  ]

  # Tests that need a wide entry-point set in a single scan so the engine can
  # discover cross-request relationships (e.g. payload submitted in one endpoint
  # and reflected in another). Run these once on the union of candidate buckets
  # instead of repeating them inside per-bucket scans.
  CROSS_EP_TESTS = [
    "stored_xss",
  ]

  OTHER_TESTS = [
    "amazon_s3_takeover",
    "bopla",
    "broken_saml_auth",
    "brute_force_login",
    "business_constraint_bypass",
    "common_files",
    "cookie_security",
    "csrf",
    "css_injection",
    "cve_test",
    "date_manipulation",
    "default_login_location",
    "directory_listing",
    "email_injection",
    "excessive_data_exposure",
    "file_upload",
    "full_path_disclosure",
    "graphql_introspection",
    "header_security",
    "html_injection",
    "http_method_fuzzing",
    "id_enumeration",
    "iframe_injection",
    "improper_asset_management",
    "insecure_tls_configuration",
    "insecure_output_handling",
    "jwt",
    "ldapi",
    "lfi",
    "nosql",
    "open_cloud_storage",
    "open_database",
    "osi",
    "prompt_injection",
    "proto_pollution",
    "retire_js",
    "rfi",
    "secret_tokens",
    "server_side_js_injection",
    "sqli",
    "ssrf",
    "ssti",
    "unvalidated_redirect",
    "version_control_systems",
    "wordpress",
    "xpathi",
    "xss",
    "xxe",
  ]

  STATIC_EXTENSIONS = [
    ".js",
    ".css",
    ".map",
    ".scss",
    ".md",
  ]

  class Scan
    # Default values
    @project_id : String
    @api_key : String
    @cluster : String
    # Optional values
    @repeater_id : String?
    @api_domains : Array(String)? # Array of domains for the API test.
    @bac_aos : Array(String)?     # Array of AOs for the BAC test.
    @template_id : String?        # Template ID for scans

    # Hash of the EP status found in the project.
    @new_urls : Array(EP) = Array(EP).new
    @changed_urls : Array(EP) = Array(EP).new
    @vulnerable_urls : Array(EP) = Array(EP).new
    @tested_urls : Array(EP) = Array(EP).new

    # Buckets for the different types of EPs.
    # We will use these to scan them with the right tests.
    @apis : Array(EP) = Array(EP).new
    @static : Array(EP) = Array(EP).new
    @posts : Array(EP) = Array(EP).new
    @html : Array(EP) = Array(EP).new
    @xml : Array(EP) = Array(EP).new
    @other : Array(EP) = Array(EP).new

    @debug : Bool = false   # For debugging purposes to console.
    @ep_limit : Bool = true # For hard limit 2k EPs per-scan.
    @evaluated : Bool = false

    def initialize(@api_key, @project_id, @cluster, @repeater_id = nil, @api_domains = nil, @bac_aos = nil, @template_id = nil)
    end

    def loop
      populate
      loop do
        total = @new_urls.size + @changed_urls.size + @vulnerable_urls.size + @tested_urls.size
        puts ""
        puts "  ━━━ Project Summary ━━━".colorize(:light_cyan)
        puts ""
        puts "    ● #{"%6d" % @new_urls.size} New".colorize(:green)
        puts "    ● #{"%6d" % @changed_urls.size} Changed".colorize(:yellow)
        puts "    ● #{"%6d" % @vulnerable_urls.size} Vulnerable".colorize(:red)
        puts "    ○ #{"%6d" % @tested_urls.size} Tested".colorize(:dark_gray)
        puts "    ────────────────────".colorize(:dark_gray)
        puts "    Σ  #{"%6d" % total} Total".colorize(:white)
        puts ""
        puts "  #{"┌─────────────────────────────────────────┐".colorize(:dark_gray)}"
        puts "  #{"│".colorize(:dark_gray)} #{"s".colorize(:light_cyan)}  Scan          #{"ea".colorize(:light_cyan)} Evaluate All    #{"│".colorize(:dark_gray)}"
        puts "  #{"│".colorize(:dark_gray)} #{"r".colorize(:light_cyan)}  Refresh        #{"en".colorize(:light_cyan)} Evaluate New    #{"│".colorize(:dark_gray)}"
        puts "  #{"│".colorize(:dark_gray)} #{"lo".colorize(:light_cyan)} List Other     #{"q".colorize(:light_cyan)}  Quit            #{"│".colorize(:dark_gray)}"
        puts "  #{"└─────────────────────────────────────────┘".colorize(:dark_gray)}"
        print "  #{"❯".colorize(:light_cyan)} "
        input = gets.to_s.chomp.downcase
        case input
        when "s", "scan"
          setup_bac_test
        when "r", "refresh"
          populate
        when "ea", "evaluate all"
          evaluate
        when "en", "evaluate new & changed"
          evaluate(true)
        when "lo", "list other"
          unless @evaluated
            puts "  #{"✘".colorize(:red)} You must evaluate the URLs before listing them."
            next
          end
          puts ""
          puts "  ━━━ Other Endpoints ━━━".colorize(:light_cyan)
          @other.each do |ep|
            puts "    #{ep.method.colorize(:yellow)} #{ep.url}"
          end
          puts ""
        when "q", "quit"
          puts "\n  #{"✨".colorize(:light_cyan)} Goodbye!\n"
          exit 0
        end
      end
    end

    private def setup_bac_test
      unless @evaluated
        puts "  #{"✘".colorize(:red)} You must evaluate the URLs before scanning them."
        return
      end

      if @apis.empty?
        return scan # default to normal scan without BAC test
      end

      # Check if the BAC test contain any elements.
      unless bac = @bac_aos
        return scan # default to normal scan without BAC test
      end

      unless bac.size > 1
        puts "  #{"✘".colorize(:red)} BAC test requires at least 2 AOs."
        puts "  #{"⚠".colorize(:yellow)} Running scan without BAC test."
        return scan
      end

      # Validate AO format - can be "null" or Bright UUID.
      bac.each do |ao|
        unless ao == "null" || ao.matches?(/^[a-zA-Z0-9]+$/)
          puts "  #{"✘".colorize(:red)} Invalid AO format: #{ao}. Must be 'null' or alphanumeric."
          return
        end
      end

      puts "  #{"✔".colorize(:green)} Adding BAC test with AOs: #{bac.join(", ")}"

      api_tests = API_TESTS.dup
      api_tests << "broken_access_control"
      puts "  #{"▶".colorize(:light_cyan)} Scanning APIs (with BAC)..."
      start_scan(@apis, api_tests, "API", ["body", "path", "query"])
      scan(!!bac) # Skip API scan if BAC AOs are provided.
    end

    private def scan(skip_api_scan : Bool = false)
      puts ""
      puts "  ━━━ Launching Scans ━━━".colorize(:light_cyan)
      puts ""
      scan_count = 0
      # We use the breaking by type and then we choose the test "buckets" we want to run on them.
      unless skip_api_scan || @apis.empty?
        puts "  #{"▶".colorize(:light_cyan)} API       #{@apis.size} endpoints, #{API_TESTS.size} tests"
        start_scan(@apis, API_TESTS, "API", ["body", "path", "query"])
        scan_count += 1
      end
      unless @static.empty?
        puts "  #{"▶".colorize(:light_cyan)} Static    #{@static.size} endpoints, #{STATIC_TESTS.size} tests"
        start_scan(@static, STATIC_TESTS, "STATIC")
        scan_count += 1
      end
      unless @posts.empty?
        puts "  #{"▶".colorize(:light_cyan)} POST      #{@posts.size} endpoints, #{POST_TESTS.size} tests"
        start_scan(@posts, POST_TESTS, "POST")
        scan_count += 1
      end
      unless @html.empty?
        puts "  #{"▶".colorize(:light_cyan)} HTML      #{@html.size} endpoints, #{HTML_TESTS.size} tests"
        start_scan(@html, HTML_TESTS, "HTML")
        scan_count += 1
      end
      unless @xml.empty?
        puts "  #{"▶".colorize(:light_cyan)} XML       #{@xml.size} endpoints, #{XML_TESTS.size} tests"
        start_scan(@xml, XML_TESTS, "XML")
        scan_count += 1
      end
      unless @other.empty?
        puts "  #{"▶".colorize(:light_cyan)} Other     #{@other.size} endpoints, #{OTHER_TESTS.size} tests"
        start_scan(@other, OTHER_TESTS, "OTHER")
        scan_count += 1
      end
      cross_ep = (@apis + @posts + @html + @xml + @static + @other).uniq(&.id)
      unless cross_ep.empty?
        puts "  #{"▶".colorize(:light_cyan)} CrossEP   #{cross_ep.size} endpoints, #{CROSS_EP_TESTS.size} tests"
        start_scan(cross_ep, CROSS_EP_TESTS, "CROSS_EP", ["body", "query", "path"])
        scan_count += 1
      end
      puts ""
      puts "  #{"✔".colorize(:green)} #{scan_count} scan(s) launched successfully"
    end

    private def start_scan(ep : Array(EP), tests : Array(String), type : String, locations : Array(String) = ["body", "fragment", "query"])
      return if ep.empty?

      if @ep_limit && ep.size > 2000
        ep.each_slice(2000) { |chunk| scan_request(chunk, tests, type, locations, true) }
      else
        scan_request(ep, tests, type, locations)
      end
    end

    private def scan_request(ep : Array(EP), tests : Array(String), type : String, locations : Array(String), isChunk : Bool = false)
      chunk_tag = isChunk ? "[Chunk] " : ""
      spinner = Spinner.new("Sending #{type} scan request#{isChunk ? " (chunk)" : ""}")
      spinner.start
      begin
        body = {
          tests:                tests,
          entryPointIds:        ep.map(&.id),
          attackParamLocations: locations,
          projectId:            @project_id,
          name:                 "Incremental Scan #{chunk_tag}- #{Time.utc} - #{type}",
          repeaters:            @repeater_id ? [@repeater_id.to_s] : nil,
        }

        # Add template ID if provided
        if template_id = @template_id
          body = body.merge({templateId: template_id})
        end

        if bac = @bac_aos
          if type == "API" && tests.includes?("broken_access_control")
            test_metadata = {
              "broken_access_control" => {
                "authObjectId" => bac.map { |ao| ao == "null" ? nil : ao },
              },
            }
            body = body.merge({testMetadata: test_metadata})
          end
        end

        response = get("/api/v1/scans", "POST", body: body.to_json)
        spinner.stop("#{type} scan#{isChunk ? " (chunk)" : ""} submitted")
        debug("Request body: #{body.to_json}")
        debug("Response: #{response}")
      rescue e : JSON::ParseException
        spinner.stop
        puts "  #{"✘".colorize(:red)} Error starting #{type} scan: #{e}"
      end
    end

    private def evaluate(skip : Bool = false)
      @apis.clear
      @static.clear
      @posts.clear
      @html.clear
      @xml.clear
      @other.clear

      count = 0
      skipped = 0
      if skip
        total = @new_urls.size + @changed_urls.size
        full = [@new_urls, @changed_urls]
      else
        total = @new_urls.size + @changed_urls.size + @vulnerable_urls.size + @tested_urls.size
        full = [@new_urls, @changed_urls, @vulnerable_urls, @tested_urls]
      end

      puts ""
      puts "  ━━━ Evaluating Endpoints ━━━".colorize(:light_cyan)
      puts ""

      full.flatten.each do |ep|
        count += 1
        if ep.connectivity == "unreachable" || ep.connectivity == "unauthorized"
          skipped += 1
          debug("Skipping: #{ep.url} - #{ep.connectivity}")
          next
        end
        print "\r  #{SPINNER_FRAMES[count % SPINNER_FRAMES.size].colorize(:light_cyan)} #{Incremental.progress_bar(count, total)}  "
        select_tests(ep)
      end
      @evaluated = true
      print "\r#{" " * 80}\r"
      puts "  #{"✔".colorize(:green)} Evaluation complete"
      if skipped > 0
        puts "    #{"(#{skipped} skipped — unreachable/unauthorized)".colorize(:dark_gray)}"
      end
      puts ""
      puts "    #{"▸".colorize(:light_cyan)} #{"%5d" % @apis.size} API endpoints"
      puts "    #{"▸".colorize(:light_cyan)} #{"%5d" % @static.size} Static files (JS/CSS/etc)"
      puts "    #{"▸".colorize(:light_cyan)} #{"%5d" % @posts.size} POST endpoints"
      puts "    #{"▸".colorize(:light_cyan)} #{"%5d" % @html.size} HTML pages"
      puts "    #{"▸".colorize(:light_cyan)} #{"%5d" % @xml.size} XML resources"
      puts "    #{"▸".colorize(:light_cyan)} #{"%5d" % @other.size} Other"
      puts ""
    end

    private def select_tests(ep : EP)
      found_tests = false
      path = URI.parse(ep.url).path.to_s
      debug("Evaluating: #{ep.url} - #{path}")

      if api?(ep, path)
        @apis << ep
        found_tests = true
      end

      if STATIC_EXTENSIONS.any? { |ext| path.ends_with?(ext) } || ep.method == "GET" && URI.parse(ep.url).query.nil? && URI.parse(ep.url).fragment.nil?
        @static << ep
        found_tests = true
      end

      if ep.method == "POST" || ep.method == "PUT"
        @posts << ep
        found_tests = true
      end

      unless found_tests # This means we need more info on the EP and will have to make another request.
        begin
          res = get("/api/v2/projects/#{@project_id}/entry-points/#{ep.id}")
          ep_obj = JSON.parse(res)
          response = ep_obj["response"]?
          return unless response
          content_type = (response["headers"]["Content-Type"]? || response["headers"]["content-type"]?).to_s
          case content_type
          when .includes?("html")
            @html << ep
          when .includes?("xml")
            @xml << ep
          when .includes?("json")
            @apis << ep
          when .includes?("javascript")
            @static << ep
          when .includes?("css")
            @static << ep
          when .includes?("plain")
            @static << ep
          when .includes?("octet-stream")
            @static << ep
          when .includes?("font")
            @static << ep
          else
            @other << ep
          end
        rescue e : JSON::ParseException
          puts "  #{"✘".colorize(:red)} Error parsing JSON: #{e}"
        rescue e : Exception
          puts "  #{"✘".colorize(:red)} Error: #{e}"
        end
      end
    end

    private def api?(ep : EP, path : String) : Bool
      # Normal check conditions
      if path.includes?("/api/") || path.includes?("/graphql") || path.includes?("/rest/") || path.matches?(/\/v[0-9]+\//)
        return true
      end

      # Check if the URL is a valid API URL.
      if domains = @api_domains
        domains.any? do |domain|
          begin
            uri = URI.parse(ep.url)
            base = "#{uri.host}#{uri.port ? ":#{uri.port}" : ""}"
            match = base.starts_with?(domain) || base == domain
            debug("API domain check: #{base} against #{domain} - #{match ? "matched" : "no match"}")
            if match # this must be like this otherwise we will fail query params.
              return true
            end
          rescue e : Exception
            debug("URL parse error: #{ep.url} - #{e.message}")
            false
          end
        end
      end

      return false
    end

    private def populate
      overall_eps = Array(EP).new
      total_count = 0
      puts ""
      puts "  ━━━ Loading Entry Points ━━━".colorize(:light_cyan)
      puts ""
      loop do
        next_id = overall_eps[-1]?.try(&.id)
        next_created_at = overall_eps[-1]?.try(&.createdAt)
        if next_id && next_created_at
          eps = get("/api/v2/projects/#{@project_id}/entry-points?limit=500&moveTo=next&nextId=#{next_id}&nextCreatedAt=#{next_created_at}")
        else
          eps = get("/api/v2/projects/#{@project_id}/entry-points?limit=500")
        end
        parsed = JSON.parse(eps)
        items = Array(EP).from_json(parsed["items"].to_json)
        total_count = parsed["total"].as_i? || 0
        break if items.size == 0
        break if items[-1]?.try &.id == overall_eps[-1]?.try &.id
        items.each do |ep|
          overall_eps << ep
        end
        print "\r  #{SPINNER_FRAMES[overall_eps.size % SPINNER_FRAMES.size].colorize(:light_cyan)} #{Incremental.progress_bar(overall_eps.size, total_count)}  "
      rescue e : JSON::ParseException
        puts "\n  #{"✘".colorize(:red)} Error parsing JSON: #{e}"
      end
      print "\r#{" " * 80}\r"
      puts "  #{"✔".colorize(:green)} Loaded #{overall_eps.size} entry points"

      @new_urls.clear
      @changed_urls.clear
      @vulnerable_urls.clear
      @tested_urls.clear

      overall_eps.each do |ep|
        case ep.status
        when "new"
          @new_urls << ep
        when "changed"
          @changed_urls << ep
        when "vulnerable"
          @vulnerable_urls << ep
        when "tested"
          @tested_urls << ep
        end
      end
    end

    private def get(path : String, method : String = "GET", body : String = "") : String
      uri = URI.parse("https://#{@cluster}/#{path.lstrip("/")}")
      HTTP::Client.exec(
        method: method,
        url: uri,
        headers: HTTP::Headers{
          "Authorization" => "Api-Key #{@api_key}",
          "Content-Type"  => "application/json",
          "Accept"        => "application/json",
        },
        body: body
      ).body.to_s
    end

    private def debug(*messages)
      return unless @debug

      timestamp = Time.utc.to_s("%H:%M:%S")
      messages.each do |message|
        puts "[DEBUG][#{timestamp}] #{message}".colorize(:cyan)
      end
    end
  end

  struct EP
    include JSON::Serializable
    getter id : String
    getter url : String
    getter status : String
    getter createdAt : String
    getter method : String
    getter connectivity : String
    getter parametersCount : Int32
  end
end

# Default values
api_key = ""
project_id = ""
# Optional values
cluster = "app.brightsec.com" # Default cluster can be switched with eu.brightsec.com
repeater_id = nil             # Repeater ID
api_domains = nil             # Array of domains for the API test.
bac_aos = nil                 # Array of AOs for the BAC test.
template_id = nil             # Template ID for scans

def cluster_format?(arg) : Bool
  arg.ends_with?(".brightsec.com")
end

def api_key_connect?(api_key : String, project_id : String, cluster : String) : Bool
  path = "api/v1/projects/#{project_id}"
  uri = URI.parse("https://#{cluster}/#{path.lstrip("/")}")

  response = HTTP::Client.exec(
    method: "GET",
    url: uri,
    headers: HTTP::Headers{
      "Authorization" => "Api-Key #{api_key}",
      "Content-Type"  => "application/json",
      "Accept"        => "application/json",
    },
    body: ""
  )
  unless response.status_code == 200
    STDERR.puts "  #{"✘".colorize(:red)} Auth failed (#{response.status_code}): #{response.body.to_s}"
  end
  return response.status_code == 200
end

parser = OptionParser.parse do |parser|
  parser.banner = "Usage: incremental -k <api_key> -p <project_id> [OPTIONS]"
  parser.separator("\nRequired arguments:")
  parser.on("-k KEY", "--api-key=KEY", "Your Bright API Key") { |v| api_key = v }
  parser.on("-p PROJECT", "--project-id=PROJECT", "Bright Project ID") { |v| project_id = v }

  parser.separator("\nOptional arguments:")
  parser.on("-c CLUSTER", "--cluster=CLUSTER", "Bright cluster (default: app.brightsec.com)") do |v|
    if cluster_format?(v)
      cluster = v
    else
      puts "Invalid cluster format: #{v}".colorize(:red)
      puts "Please use a valid cluster like app.brightsec.com or eu.brightsec.com".colorize(:yellow)
      exit 1
    end
  end
  parser.on("-r REPEATER", "--repeater-id=REPEATER", "ID of your Bright repeater") { |v| repeater_id = v }
  parser.on("-a DOMAINS", "--api-domains=DOMAINS", "Comma-separated list of API domains (helps identify API endpoints)") { |v| api_domains = v.split(",") }
  parser.on("-b AOS", "--bac-aos=AOS", "Comma-separated list of Auth Objects (for testing BAC vulnerabilities)") { |v| bac_aos = v.split(",") }
  parser.on("-t TEMPLATE", "--template-id=TEMPLATE", "Template ID for scans") { |v| template_id = v }
  parser.on("-h", "--help", "Show this help") do
    puts parser
    puts "\nExamples:".colorize(:green)
    puts "  Basic scan:".colorize(:yellow)
    puts "    incremental -k orgSecretKey  -p projectID"
    puts "  Advanced scan with repeater:".colorize(:yellow)
    puts "    incremental -k orgSecretKey  -p projectID -r myRepeaterId -c eu.brightsec.com"
    puts "  API-focused scan:".colorize(:yellow)
    puts "    incremental -k orgSecretKey  -p projectID -a api.example.com,api2.example.com:7777"
    puts "  Scan with template:".colorize(:yellow)
    puts "    incremental -k orgSecretKey  -p projectID -t templateId123"
    puts ""
    exit 0
  end
  parser.on("-v", "--version", "Show version") do
    puts Incremental::VERSION
    exit 0
  end
end

if api_key.empty? || project_id.empty?
  puts parser
  exit 1
end

puts Incremental::BANNER
puts ""

spinner = Incremental::Spinner.new("Connecting to #{cluster}")
spinner.start
unless api_key_connect?(api_key, project_id, cluster)
  spinner.stop
  puts "  #{"✘".colorize(:red)} Connection failed. Check your API key and cluster (app.brightsec.com / eu.brightsec.com)."
  exit 1
end
spinner.stop("✔".colorize(:green).to_s + " Connected to #{cluster}")

scan = Incremental::Scan.new(api_key, project_id, cluster, repeater_id, api_domains, bac_aos, template_id)
scan.loop
