# Cape CLI

## Usage

The CLI for [Cape Privacy](https://capeprivacy.com)

See https://docs.capeprivacy.com/getting-started for documentation.

## Developing

### Building

```
go build ./cmd/cape
```

### Config

For login purposes the following environment variables can be configured:

```
CAPE_AUTH_HOST                   String    https://login.capeprivacy.com
CAPE_ENCLAVE_HOST                String    https://app.capeprivacy.com
CAPE_CLIENT_ID                   String    yQnobkOr1pvdDAyXwNojkNV2IPbNfXxx
CAPE_AUDIENCE                    String    https://app.capeprivacy.com/v1/
CAPE_LOCAL_CONFIG_DIR            String    ~/.config/cape
CAPE_LOCAL_AUTH_FILE_NAME        String    auth
```

These can be configured through a config file, env variables, or command line flags.
For example, to override the default value and route to a different enclave host:
```
cape config enclave_host https://app.capeprivacy.com   //set the value in ~/.config/cape/presets.json
export CAPE_ENCLAVE_HOST=https://app.capeprivacy.com   //set env variable that the cli will pick up
cape deploy app --url https://app.capeprivacy.com     //set the url for just this command
```
These options are provided in order of priority, and the value from the higher priority one will override a lower priority one. Ex: Command line value will always be used in case of conflict with same parameter in env variables or file preset.
