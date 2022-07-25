# cli

Cape CLI

## Overview

### Install

#### Without Go

If you have golang installed you can alternatively use [go to install Cape](#with-go).

In a browser go to https://github.com/capeprivacy/cli/releases and choose a release and OS/Architecture
package you'd like to download and download it.

`curl` can also be used to donwload the files, like:

```
curl -O https://github.com/capeprivacy/cli/releases/download/v0.0.1/cape_0.0.1_Linux_x86_64.tar.gz
```

Then untar the binary into `/usr/bin` or another location that is in your `$PATH`.

```
$ tar -C /usr/bin -xzf cape_0.0.1_Linux_x86_64.tar.gz
```

`sudo` may be required on the above command.

#### With Go

Cape CLI can be simply installed with:

```
go install github.com/capeprivacy/cli/cmd/cape
```

Note: Make sure your $HOME/go/bin directory is in your $PATH.

### Cape Login

Log into Cape by running `cape login`:

```
$ cape login
Your CLI confirmation code is: <RANDOM CODE>
Visit this URL to complete the login process: https://maestro-dev.us.auth0.com/activate?user_code=<RANDOM CODE>
```

If your terminal is able to it will auto-launch a browser. Finish the log in process and confirm that the code matches
the code you are seeing in the browser. If your terminal can't launch a browser you can manually visit the link and complete
the process that way.

### Run Simple Test Function

While developing the function you want to run in Cape you can simple use the `cape test` command
to test against an actual enclave. In the example below there is a file containing the input data and a
directory containing the function to be run.

```
$ ls
input_data test_func

$ cape test test_func input_data
Success! Results from your function:
<RESULTS GO HERE>
```

Any logging output is output to stderr while results are output to stdout.

See `cape test --help` for more options.

### Deploy Function

Once your function is finalized you can deploy it to Cape for future use using `cape deploy`. The set up is similar
to `cape test`.

```
$ ls
test_func

$ cape deploy test_func
Success! Deployed function to Cape\nFunction ID ➜ <FUNCTION ID>\n
```

`<FUNCTION ID>` is a UUID that will then be used to pass to `cape run`.

See `cape deploy --help` for more options.

### Run Function

You and other users can use your deployed function by running the `cape run` command:

```
$ ls
input_data

$ cape run <FUNCTION ID> input_data
Success! Results from your function:
<RESULTS GO HERE>
```

Any tracing output is output to stderr while results are output to stdout.

See `cape run --help` for more options.

## Build

```
go build ./cmd/cape
```

## Config

For login purposes the following environment variables can be configured:

```
CAPE_AUTH_HOST                   String    https://maestro-dev.us.auth0.com
CAPE_ENCLAVE_HOST                String    wss://hackathon.capeprivacy.com
CAPE_CLIENT_ID                   String    yQnobkOr1pvdDAyXwNojkNV2IPbNfXxx
CAPE_AUDIENCE                    String    https://newdemo.capeprivacy.com/v1/
CAPE_LOCAL_CONFIG_DIR            String    ~/.config/cape
CAPE_LOCAL_AUTH_FILE_NAME        String    auth
```

These can be configured through a config file, env variables, or command line flags.
For example, to override the default value and route to a different enclave host:
```
cape config enclave_host wss://run.capeprivacy.com   //set the value in ~/.config/cape/presets.json
export CAPE_ENCLAVE_HOST=wss://run.capeprivacy.com   //set env variable that the cli will pick up
cape deploy app --url wss://run.capeprivacy.com      //set the url for just this command
```
These options are provided in order of priority, and the value from the higher priority one will override a lower priority one. Ex: Command line value will always be used in case of conflict with same parameter in env variables or file preset.
