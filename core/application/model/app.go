package model

// Application struct
type Application struct {
	Name         string `json:"name"`
	ClientID     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
	RedirectURI  string `json:"redirectUri"`
}

// IsValidClientSecret function
func (a *Application) IsValidClientSecret(clientSecret string) bool {
	return a.ClientSecret == clientSecret
}
