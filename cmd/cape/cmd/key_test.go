package cmd

import (
	"errors"
	"testing"

	"github.com/capeprivacy/cli/sdk"
)

func TestKeyNoArgs(t *testing.T) {
	cmd, stdout, stderr := getCmd()
	cmd.SetArgs([]string{"key"})

	want := `-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAoM2iIWF9ocxYGsSUnyt9
P7NLq3gv39uNJCdIGee/y8EQHhFEg6cJONPJP60E/3Zt4hnrYh4a4lx7rV0aWks5
KxpQi6LPP98sUKLkZO/ZTcY5Ugtn7FAQNj19ohtI39c2WCgxUB/1IR485jE1SLFn
x351mcog4V3pdU6THK1ZQTNhkonsLwyaP5TzpKySpz+OlgOBNDxqm6iRb7BQrc/w
hYj8Fpfj92m83cWk+jhlqUQwjMZ3b0B9jmSfzUNmEZEng/+Bw9hFpMH48LOsAHwg
z5tC1RhuGI5Is6VaKUeKbnptZQREIcXcs2857h+1i6EVW11shn4IRpOl3nvFoU+t
SDwpOQXs7oFcsEWz+qhpknMcQfd/fv/z4FSUuvStzlNO6bsGm8KBNtXLjTbhK4V7
Q44KcYulow/Dp4Rq3Pf+ZHgoqpfqujspWV1Sh++u6rPCte8lMozEIVd1scaCWw9S
w1id8sguJTfgccx1HBbp76q0U2zojfQf+EAyMHwN0/4JnqZ1mJZPhi9nGpnINZuy
wBsNPjtORYiDYLdLY7VL/O/tXsX03uVKfu6mQZNxhOSR2sD6AoEi/LaECMM+L96Q
EhOGvy7wILr1Zjc6KlUksXKOlXeKhJ0xxwcBWMznJG82WzeNczQ14I+I9RdkLUtP
vbU0SB7H7aX/bxqvQ+MOwS8CAwEAAQ==
-----END PUBLIC KEY-----
`

	keyFunc = func(keyReq sdk.KeyRequest) ([]byte, error) {
		return []byte("0\x82\x02\"0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x01\x05\x00\x03\x82\x02\x0f\x000\x82\x02\n\x02\x82\x02\x01\x00\xa0͢!a}\xa1\xccX\x1aĔ\x9f+}?\xb3K\xabx/\xdfۍ$'H\x19\xe7\xbf\xcb\xc1\x10\x1e\x11D\x83\xa7\t8\xd3\xc9?\xad\x04\xffvm\xe2\x19\xebb\x1e\x1a\xe2\\{\xad]\x1aZK9+\x1aP\x8b\xa2\xcf?\xdf,P\xa2\xe4d\xef\xd9M\xc69R\vg\xecP\x106=}\xa2\x1bH\xdf\xd76X(1P\x1f\xf5!\x1e<\xe615H\xb1g\xc7~u\x99\xca \xe1]\xe9uN\x93\x1c\xadYA3a\x92\x89\xec/\f\x9a?\x94\U000e4b12\xa7?\x8e\x96\x03\x814<j\x9b\xa8\x91o\xb0P\xad\xcf\xf0\x85\x88\xfc\x16\x97\xe3\xf7i\xbc\xddŤ\xfa8e\xa9D0\x8c\xc6wo@}\x8ed\x9f\xcdCf\x11\x91'\x83\xff\x81\xc3\xd8E\xa4\xc1\xf8\xf0\xb3\xac\x00| ϛB\xd5\x18n\x18\x8eH\xb3\xa5Z)G\x8anzme\x04D!\xc5ܳo9\xee\x1f\xb5\x8b\xa1\x15[]l\x86~\bF\x93\xa5\xde{šO\xadH<)9\x05\xec\xee\x81\\\xb0E\xb3\xfa\xa8i\x92s\x1cA\xf7\x7f~\xff\xf3\xe0T\x94\xba\xf4\xad\xceSN\xe9\xbb\x06\x9b\u00816\xd5ˍ6\xe1+\x85{C\x8e\nq\x8b\xa5\xa3\x0fç\x84j\xdc\xf7\xfedx(\xaa\x97\xea\xba;)Y]R\x87\xef\xae\xea\xb3µ\xef%2\x8c\xc4!Wu\xb1Ƃ[\x0fR\xc3X\x9d\xf2\xc8.%7\xe0q\xccu\x1c\x16\xe9華Sl\xe8\x8d\xf4\x1f\xf8@20|\r\xd3\xfe\t\x9e\xa6u\x98\x96O\x86/g\x1a\x99\xc85\x9b\xb2\xc0\x1b\r>;NE\x88\x83`\xb7Kc\xb5K\xfc\xef\xed^\xc5\xf4\xde\xe5J~\xee\xa6A\x93q\x84\xe4\x91\xda\xc0\xfa\x02\x81\"\xfc\xb6\x84\b\xc3>/ސ\x12\x13\x86\xbf.\xf0 \xba\xf5f7:*U$\xb1r\x8e\x95w\x8a\x84\x9d1\xc7\a\x01X\xcc\xe7$o6[7\x8ds45\xe0\x8f\x88\xf5\x17d-KO\xbd\xb54H\x1e\xc7\xed\xa5\xffo\x1a\xafC\xe3\x0e\xc1/\x02\x03\x01\x00\x01"), nil
	}
	authToken = func() (string, error) {
		return "you're you", nil
	}
	defer func() {
		keyFunc = sdk.Key
		authToken = getAuthToken
	}()

	if err := cmd.Execute(); err != nil {
		t.Fatalf("received unexpected error: %s", err)
	}

	if got, want := stderr.String(), ""; got != want {
		t.Fatalf("didn't get expected stderr, got %s, wanted %s", got, want)
	}

	if got, want := stdout.String(), want; got != want {
		t.Fatalf("didn't get expected stdout, got %s, wanted %s", got, want)
	}
}

func TestKeyInvalidFormat(t *testing.T) {
	cmd, _, _ := getCmd()
	cmd.SetArgs([]string{"key"})

	keyFunc = func(keyReq sdk.KeyRequest) ([]byte, error) {
		return []byte("-----BEGIN PUBLIC KEY-----\nTestKey\n-----END PUBLIC KEY-----\n"), nil
	}
	authToken = func() (string, error) {
		return "you're you", nil
	}
	defer func() {
		keyFunc = sdk.Key
		authToken = getAuthToken
	}()

	err := cmd.Execute()
	if err == nil {
		t.Fatalf("expected an error: %s", err)
	}

	if !errors.As(err, &UserError{}) {
		t.Fatalf("expected different error: %s", err)
	}
}
