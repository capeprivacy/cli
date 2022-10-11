package sdk

/**
connect:
mock out websocketDial and test doDial. or mock out just the bits with the real ws
for the scope of these tests, mock out websocket stuff entirely
getProtocol
attest funcs
pcrs are doable if we fake the attdoc or don't use any in test

invoke (incl writeData):
replace websocket.Conn with interface in signatures
use mocked conn and verify calls thereto
...can we do this? getProtocol needs to pass a websocket.Conn to the proto.Protocol internally

thor's idea: make a dummy ws server
should be fairly simple
send predefined messages, testing the client, not the server
we shouldn't test the message sent to the server in this case
*/

//func Test_connect(t *testing.T) {
//	type args struct {
//		url          string
//		functionID   string
//		functionAuth entities.FunctionAuth
//		funcChecksum []byte
//		keyChecksum  []byte
//		pcrSlice     []string
//		insecure     bool
//	}
//	tests := []struct {
//		name    string
//		args    args
//		want    *websocket.Conn
//		want1   *attest.AttestationDoc
//		wantErr bool
//	}{
//		// TODO: Add test cases.
//	}
//	for _, tt := range tests {
//		t.Run(tt.name, func(t *testing.T) {
//			got, got1, err := connect(tt.args.url, tt.args.functionID, tt.args.functionAuth, tt.args.funcChecksum, tt.args.keyChecksum, tt.args.pcrSlice, tt.args.insecure)
//			if (err != nil) != tt.wantErr {
//				t.Errorf("connect() error = %v, wantErr %v", err, tt.wantErr)
//				return
//			}
//			if !reflect.DeepEqual(got, tt.want) {
//				t.Errorf("connect() got = %v, want %v", got, tt.want)
//			}
//			if !reflect.DeepEqual(got1, tt.want1) {
//				t.Errorf("connect() got1 = %v, want %v", got1, tt.want1)
//			}
//		})
//	}
//}
//
//func Test_invoke(t *testing.T) {
//	type args struct {
//		doc  *attest.AttestationDoc
//		conn *websocket.Conn
//		data []byte
//	}
//	tests := []struct {
//		name    string
//		args    args
//		want    []byte
//		wantErr bool
//	}{
//		// TODO: Add test cases.
//	}
//	for _, tt := range tests {
//		t.Run(tt.name, func(t *testing.T) {
//			got, err := invoke(tt.args.doc, tt.args.conn, tt.args.data)
//			if (err != nil) != tt.wantErr {
//				t.Errorf("invoke() error = %v, wantErr %v", err, tt.wantErr)
//				return
//			}
//			if !reflect.DeepEqual(got, tt.want) {
//				t.Errorf("invoke() got = %v, want %v", got, tt.want)
//			}
//		})
//	}
//}
