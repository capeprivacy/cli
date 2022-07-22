package config

type Config struct {
	EnclaveHost       string
	AuthHost          string
	ClientID          string
	Audience          string
	LocalConfigDir    string
	LocalAuthFileName string

	// Dev only
	Insecure bool
}
