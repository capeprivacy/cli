# cli

Cape CLI

## Overview

### One-shot Function

```
$ ls
input_data func.py

$ cape test func.py input_data
Successfully ran function. Your results are '<RESULTS GO HERE>'
```

## Build

```
go build -o cape main.go
```

## Config
For login purposes the following environment variables can be configured:
```
CLI_HOSTNAME                String    https://maestro-dev.us.auth0.com
CLI_CLIENT_ID               String    yQnobkOr1pvdDAyXwNojkNV2IPbNfXxx
CLI_AUDIENCE                String    https://newdemo.capeprivacy.com/v1/
CLI_LOCAL_AUTH_DIR          String    .cape
CLI_LOCAL_AUTH_FILE_NAME    String    auth
```
