# incremental

A simple CLI to run incremental BrightSec scans.

```bash
  ━━━ Loading Project Data ━━━

  ✔ Loaded 1002 entry points

  ━━━ Project Data ━━━

    Project ID    6824abcd-1234
    Project Name  My Web App

    ● New           1002
    ● Changed          0
    ● Vulnerable       0
    ○ Tested           0
    ────────────────────
    Σ Total         1002

  ┌──────────────────────────────────────┐
  │ s  Scan           ea Evaluate All    │
  │ r  Refresh        en Evaluate New    │
  │ lo List Other     le List Excessive  │
  │ q  Quit                              │
  └──────────────────────────────────────┘
```

## Installation

1. [Install Crystal](https://crystal-lang.org/docs/installation/)
2. `git clone` this repo
3. `cd` into the repo
4. `shards build`

## Usage

```bash
Usage: incremental -k <api_key> -p <project_id> [OPTIONS]

Required arguments:
    -k KEY, --api-key=KEY            Your Bright API Key
    -p PROJECT, --project-id=PROJECT
                                     Bright Project ID

Optional arguments:
    -c CLUSTER, --cluster=CLUSTER    Bright cluster (default: app.brightsec.com)
    -r REPEATER, --repeater-id=REPEATER
                                     ID of your Bright repeater
    -a DOMAINS, --api-domains=DOMAINS
                                     Comma-separated list of API domains (helps identify API endpoints)
    -b AOS, --bac-aos=AOS            Comma-separated list of Auth Objects (for testing BAC vulnerabilities)
    -t TEMPLATE, --template-id=TEMPLATE
                                     Template ID for scans
    -m PARAMS, --max-params=PARAMS   Flag EPs with more parameters than this (default: 300)
    -s, --skip-excessive             Automatically skip endpoints with > max-params (no prompt)
    -C N, --concurrency=N            Max concurrent requests per scan (1-50)
    -R N, --request-rate-limit=N     Requests per second per scan (1-1000)
    -h, --help                       Show this help
    -v, --version                    Show version
```

### Tuning scan load

Use `-C/--concurrency` to cap concurrent requests (`poolSize`, 1-50) and `-R/--request-rate-limit` to cap requests per second (`requestsRateLimit`, 1-1000). When omitted, Bright applies its own defaults.

```bash
incremental -k <api_key> -p <project_id> -C 25 -R 200
```

### Docker usage

1. clone the repo
2. `cd` into the repo
3. `docker build -t incremental .`

```bash
docker run -it incremental -k <api_key> -p <project_id> -c <cluster> -r <repeater_id>
```

## Contributing

1. Fork it (<https://github.com/NeuraLegion/incremental/fork>)
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request

## Contributors

- [Bar Hofesh](https://github.com/bararchy) - creator and maintainer
- [Dor Shaer](https://github.com/dorshaer) - maintainer
