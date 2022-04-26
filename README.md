# cli

Cape CLI

## Overview

```
$ ls
input_data func.py

$ cape encrypt func.py
Successfully encrypted and attested. File written to func.py.cape. Your secret is pczcC+ti12N7iAhFduyHEaiil3kJV0DGHCsCC37T+5U=

$ ls
input_data func.py func.py.cape

$ cape encrypt input_data
Successfully encrypted and attested. File written to input_data.cape. Your secret is KH+VNX9WUJtuzkSMB2EW38zYJtNLty5nwsANkXW2Amw=

$ ls
input_data func.py func.py.cape input_data.cape

$ cape run func.py.cape pczcC+ti12N7iAhFduyHEaiil3kJV0DGHCsCC37T+5U= input_data.cape KH+VNX9WUJtuzkSMB2EW38zYJtNLty5nwsANkXW2Amw=
Successfully ran function. Your results are '<RESULTS GO HERE>'
```

## Build

```
go build -o cape main.go
```
