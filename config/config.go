package config

type LoginConfig struct {
	Hostname          string `default:"https://maestro-dev.us.auth0.com" split_words:"true"`
	ClientID          string `default:"yQnobkOr1pvdDAyXwNojkNV2IPbNfXxx" split_words:"true"`
	Audience          string `default:"https://newdemo.capeprivacy.com/v1/" split_words:"true"`
	LocalAuthDir      string `default:".cape" split_words:"true"`
	LocalAuthFileName string `default:"auth" split_words:"true"`
}

type Config struct {
	Login LoginConfig
}
