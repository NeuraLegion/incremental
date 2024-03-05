# incremental

A simple CLI to run incremental BrightSec scans.

```bash
Scanning APIs...
Scanning JS...
Scanning POSTs...
Scanning HTML...
Scanning XML...
Scanning other...
Done spawning scans
Project Summary
---------------
New: 128
Vulnerable: 0
Tested: 0
---------------
[s\scan] [r\refresh] [ea\evaluate all] [en\evaluate new] [q\quit]
```

## Installation

1. [Install Crystal](https://crystal-lang.org/docs/installation/)
2. `git clone` this repo
3. `cd` into the repo
4. `shards build`

## Usage

```bash
Usage: incremental <api_key> <project_id> [cluster(default: app.brightsec.com)] [repeater_id]
    -k KEY, --api-key=KEY            API Key
    -p PROJECT, --project-id=PROJECT Project ID
    -c CLUSTER, --cluster=CLUSTER    Cluster
    -r REPEATER, --repeater-id=REPEATER
                                     Repeater ID
    -h, --help                       Show this help
    -v, --version                    Show version
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
