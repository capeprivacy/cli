package config

type Config struct {
	EnclaveHost       string
	SupervisorHost    string
	AuthHost          string
	ClientID          string
	Audience          string
	LocalConfigDir    string
	LocalAuthFileName string
	LocalCapeKeyFileName string

	// Dev only
	Insecure bool
}
