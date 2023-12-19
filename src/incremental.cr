require "json"
require "colorize"
require "http"

# Incremental is a CLI tool that allows you to smartly make incremental scans
# using the BrightSec API.
module Incremental
  VERSION = "0.1.0"

  API_TESTS = [
    "amazon_s3_takeover",
    "business_constraint_bypass",
    "date_manipulation",
    "file_upload",
    "full_path_disclosure",
    "graphql_introspection",
    "id_enumeration",
    "improper_asset_management",
    "jwt",
    "mass_assignment",
    "nosql",
    "osi",
    "lfi",
    "rfi",
    "sqli",
    "ssrf",
    "xxe",
    "open_buckets",
    "open_database",
  ]

  STATIC_TESTS = [
    "cve_test",
    "open_buckets",
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
    "stored_xss",
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
    "stored_xss",
    "proto_pollution",
    "server_side_js_injection",
    "header_security",
    "cookie_security",
    "css_injection",
    "directory_listing",
    "secret_tokens",
  ]

  XML_TESTS = [
    "xxe",
    "xss",
    "secret_tokens",
  ]

  OTHER_TESTS = [
    "amazon_s3_takeover",
    "angular_csti",
    "backup_locations",
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
    "excessive_data_exposure",
    "exposed_couch_db_apis",
    "file_upload",
    "full_path_disclosure",
    "graphql_introspection",
    "header_security",
    "html_injection",
    "http_method_fuzzing",
    "id_enumeration",
    "improper_asset_management",
    "insecure_tls_configuration",
    "jwt",
    "ldapi",
    "lfi",
    "mass_assignment",
    "nosql",
    "open_buckets",
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
    "stored_xss",
    "unvalidated_redirect",
    "version_control_systems",
    "webdav",
    "wordpress",
    "xpathi",
    "xss",
    "xxe",
  ]

  class Scan
    @project_id : String
    @api_key : String
    @cluster : String

    # This will be a hash of the new URLs found in the scan.
    # We save them as URL -> EP ID.
    @new_urls : Array(EP) = Array(EP).new

    # This will be a hash of the vulnerable URLs found in the scan.
    @vulnerable_urls : Array(EP) = Array(EP).new

    # This will be a hash of the tested URLs found in the scan.
    @tested_urls : Array(EP) = Array(EP).new

    @apis : Array(EP) = Array(EP).new
    @static : Array(EP) = Array(EP).new
    @posts : Array(EP) = Array(EP).new
    @html : Array(EP) = Array(EP).new
    @xml : Array(EP) = Array(EP).new
    @other : Array(EP) = Array(EP).new

    @evaluated : Bool = false

    def initialize(@api_key, @project_id, @cluster)
    end

    def loop
      populate
      loop do
        puts "Project Summary"
        puts "---------------"
        puts "New: #{@new_urls.size}".colorize(:green)
        puts "Vulnerable: #{@vulnerable_urls.size}".colorize(:red)
        puts "Tested: #{@tested_urls.size}"
        puts "---------------"
        puts "[s\\scan] [r\\refresh] [ea\\evaluate all] [en\\evaluate new] [q\\quit]"
        input = gets.to_s.chomp.downcase
        case input
        when "s", "scan"
          scan
        when "r", "refresh"
          populate
        when "ea", "evaluate all"
          evaluate
        when "en", "evaluate new"
          evaluate(true)
        when "q", "quit"
          exit 0
        end
      end
    end

    private def scan
      unless @evaluated
        puts "You must evaluate the URLs before scanning them.".colorize(:red)
        return
      end
      # Now we will scan all the EPs we have.
      # We use the breaking by type and then we choose the test "buckets" we want to run on them.
      puts "Scanning APIs...".colorize(:blue)
      start_scan(@apis, API_TESTS, "API", ["body", "path", "query"])
      puts "Scanning JS...".colorize(:blue)
      start_scan(@static, STATIC_TESTS, "JS")
      puts "Scanning POSTs...".colorize(:blue)
      start_scan(@posts, POST_TESTS, "POST")
      puts "Scanning HTML...".colorize(:blue)
      start_scan(@html, HTML_TESTS, "HTML")
      puts "Scanning XML...".colorize(:blue)
      start_scan(@xml, XML_TESTS, "XML")
      puts "Scanning other...".colorize(:blue)
      start_scan(@other, OTHER_TESTS, "OTHER")
      puts "Done spawning scans".colorize(:green)
    end

    private def start_scan(ep : Array(EP), tests : Array(String), type : String, locations : Array(String) = ["body", "fragment", "query"])
      return if ep.size == 0
      get(
        "/api/v1/scans",
        "POST",
        body: {
          tests:                tests,
          entryPointIds:        ep.map(&.id),
          attackParamLocations: locations,
          projectId:            @project_id,
          name:                 "Incremental Scan - #{Time.utc} - #{type}",
        }.to_json
      )
    end

    private def evaluate(skip : Bool = false)
      @evaluated = true
      @apis.clear
      @static.clear
      @posts.clear
      @html.clear
      @xml.clear
      @other.clear

      count = 0
      total = @new_urls.size + @vulnerable_urls.size + @tested_urls.size
      [@new_urls, @vulnerable_urls, @tested_urls].flatten.each do |ep|
        count += 1
        if skip && ep.status != "new"
          next
        end
        if ep.connectivity == "unreachable" || ep.connectivity == "unauthorized"
          next
        end
        print "\rEvaluating #{count} of #{total} URLs..."
        path = URI.parse(ep.url).path.to_s
        case
        when ep.url.includes?("/api/") || ep.url.includes?("/graphql") || ep.url.includes?("/rest/")
          @apis << ep
        when path.ends_with?(".js") || path.ends_with?(".css") || path.ends_with?(".map")
          @static << ep
        when (ep.method == "POST" || ep.method == "PUT")
          @posts << ep
        else # This means we need more info on the EP and will have to make another request.
          begin
            res = get("/api/v2/projects/#{@project_id}/entry-points/#{ep.id}")
            ep_obj = JSON.parse(res)
            response = ep_obj["response"]?
            next unless response
            case response["headers"]["Content-Type"]?.to_s
            when .includes?("html")
              @html << ep
            when .includes?("xml")
              @xml << ep
            else
              @other << ep
            end
          rescue e : JSON::ParseException
            puts "Error parsing JSON: #{e} - #{res}".colorize(:red)
          rescue e : Exception
            puts "Error: #{e}".colorize(:red)
          end
        end
      end
      puts "---------------"
      puts "Evaluated".colorize(:green)
      puts "#{@apis.size} APIs"
      puts "#{@static.size} Static files (JS/CSS/etc..)"
      puts "#{@posts.size} POSTs"
      puts "#{@html.size} HTML files."
      puts "#{@xml.size} XML files."
      puts "#{@other.size} other."
      puts "---------------"
    end

    private def populate
      overall_eps = Array(EP).new
      loop do
        next_id = overall_eps[-1]?.try(&.id)
        next_created_at = overall_eps[-1]?.try(&.createdAt)
        if next_id && next_created_at
          eps = get("/api/v2/projects/#{@project_id}/entry-points?limit=100&moveTo=next&nextId=#{next_id}&nextCreatedAt=#{next_created_at}")
        else
          eps = get("/api/v2/projects/#{@project_id}/entry-points?limit=100")
        end
        items = Array(EP).from_json(JSON.parse(eps)["items"].to_json)
        break if items.size == 0
        break if items[-1]?.try &.id == overall_eps[-1]?.try &.id
        items.each do |ep|
          overall_eps << ep
        end
        print "\rPopulating... #{overall_eps.size}/#{JSON.parse(eps)["total"]} entry points."
      rescue e : JSON::ParseException
        puts "Error parsing JSON: #{e} - #{eps}".colorize(:red)
      end

      @new_urls.clear
      @vulnerable_urls.clear
      @tested_urls.clear

      overall_eps.each do |ep|
        case ep.status
        when "new"
          @new_urls << ep
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
  end

  struct EP
    include JSON::Serializable
    getter id : String
    getter url : String
    getter status : String
    getter createdAt : String
    getter method : String
    getter connectivity : String
  end
end

if ARGV.size < 2
  puts "Usage: incremental <api_key> <project_id> [cluster - default: app.brightsec.com]"
  exit 1
end

api_key = ARGV[0]
project_id = ARGV[1]
cluster = ARGV[2]? || "app.brightsec.com"

scan = Incremental::Scan.new(api_key, project_id, cluster)
scan.loop
