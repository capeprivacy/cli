package config

type Config struct {
	Hostname          string
	ClientID          string
	Audience          string
	LocalConfigDir    string
	LocalAuthFileName string

	// Dev only
	Insecure bool
}
