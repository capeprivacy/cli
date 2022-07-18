

# Cape CLI



### Project Description

Cape Privacy Command Line Interface is the main interface used to run the Cape Privacy confidential computing environment. 

Confidential computing is the protection of data in use by performing computation in a hardware-based Trusted Execution Environment (TEE) or Secure Enclave. Confidential computing is a cloud computing technology that isolates sensitive data in a protected enclave during processing. 

Secure enclaves provide an environment for isolation of code and data from OS using hardware-based CPU-level isolation. Secure enclaves offer a process called "attestation" to verify CPU and apps running are genuine and unaltered. Secure Enclaves enable the concept of Confidential Computing.



### Project Usage

Cape CLI is only used for Cape’s confidential computing environment.



### Install

#### Download Binary

To download a binary for your platform: 

Open your browser and navigate to https://github.com/capeprivacy/cli/releasesDownload the release and OS/Architecture package of your choice. In addition, you can also use curl to download the files with the following command:

```
`curl -O https://github.com/capeprivacy/cli/releases/download/v0.0.1/cape_0.0.1_Linux_x86_64.tar.gz`
```

Then untar the binary into `/usr/bin` or another location that is in your `$PATH.`

`

```
$ tar -C /usr/bin -xzf cape_0.0.1_Linux_x86_64.tar.gz`
```

 

**Note:** If you’re not using the root account, sudo may be required on the above command.

```
$ sudo tar -C /usr/bin -xzf cape_0.0.1_Linux_x86_64.tar.gz
```



#### Go Install

If you’re a Go developer, Cape CLI can be simply installed with:

```
go install github.com/capeprivacy/cli/cmd/cape@latest 
```



**Note:** Make sure your `$HOME/go/bin` directory is in your `$PATH`. 



#### Homebrew Installation

Still being created, we’ll add instructions here once done. 



### Log in to Cape

To begin, log in to Cape using the command:

$ cape loginYour CLI confirmation code is: <RANDOM CODE>Visit this URL to complete the login process: https://login.capeprivacy.com/activate?user_code=<RANDOM CODE> 

**internal note - verify this URL in readme before opening repo*

Your terminal should auto-launch a browser with the required authorization site. Finish the login process and confirm that the code matches the code you are seeing in the browser. 

If your browser doesn’t automatically open the page you can copy and paste the link into your browser window to manually complete the login process. 



### Run Simple Test Function

While developing the function you want to use in Cape, use the cape test command to test the function you’re developing in an actual enclave. In the example provided below there’s a file containing the input data and a directory containing the function to be run.The test command incorporates both the deploy and run functions described in the sections below. 

```
$ lsinput_data test_func

$ cape test test_func input_data
Success! Results from your function:
<RESULTS GO HERE> 
```

**internal note - add some fancy gifs into this doc here of the code in terminal.* 


Any logging output is output to stderr while results are output to stdout. This provides the option to pipe the results of your program into another application. 

For example, if you’d like to format and syntax-highlight json output using jq, you could use a command like this:

```
$ cape test test_func input_data | jq ‘.’
Success! Results from your function:
<FORMATTED, COLORFUL RESULTS GO HERE>
```

For more options, use the command `cape test --help `



### Deploy Function

Deploying your function uploads the function into the Cape system and prepares it to be used with any data in the future. Your function is packaged locally and then encrypted using a public key from the enclave before being transferred into the enclave. This encryption ensures that your function is only readable from within an enclave. 

Once you’ve finalized your function, use cape deploy to store your new function for future use. The setup is similar to the cape test command.

```
$ ls
test_func

$ cape deploy test_func
Success! Deployed function to Cape
Function ID ➜ <FUNCTION ID>
```

 `<FUNCTION ID>` is a unique identifier that will then be used to pass to `cape run`.

Once deployed, the function is re-encrypted using Amazon Web Services Key Management System (AWS KMS). The now encrypted function is then stored in the Cape infrastructure system. 

For more options, use the command `cape deploy --help` 



### Run Function

The run command loads the function into the enclave, and activates your function to collate provided data. Both you as the Cape customer and your end user can use the Run function to deploy and collate data by using the cape run command:

```
$ lsinput_data
$ cape run <FUNCTION ID> input_data
Success! Results from your function:
<RESULTS GO HERE> 
```

Any logging output is output to stderr while results are output to stdout. This provides the option to pipe the results of your program into another application. 

For example, if you’d like to format and syntax-highlight json output using jq, you could use a command like this: 

```
$ cape test test_func input_data | jq ‘.’
Success! Results from your function:
<FORMATTED, COLORFUL RESULTS GO HERE>  
```

For more options, use the command `cape run --help`. 



#### Sample Function

The sample function below demonstrates usage of the run and deploy commands.

##### echo

A simple function that returns whatever you send it.

```
$ cape deploy echo
Success! Deployed function to Cape
Function ID ➜ 4b4961ef-1f04-4027-850a-3fd39a9501f2 

$ cat input.echo.data

Nana is the COOLEST

$ cape run 4b4961ef-1f04-4027-850a-3fd39a9501f2 input.echo.data

Success! Results from your function:

Nana is the COOLEST
```



### Config

For login purposes the following environment variables can be configured:

```
CAPE_HOSTNAME        String  https://maestro-dev.us.auth0.com
CAPE_CLIENT_ID        String  yQnobkOr1pvdDAyXwNojkNV2IPbNfXxx
CAPE_AUDIENCE        String  https://newdemo.capeprivacy.com/v1/
CAPE_LOCAL_AUTH_DIR     String  .cape
CAPE_LOCAL_AUTH_FILE_NAME  String  auth
```

