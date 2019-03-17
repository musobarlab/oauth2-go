package model

// OAuth2 struct
type OAuth2 struct {
	GrantType    string   `json:"grant_type"`
	Code         string   `json:"code"`
	RedirectURI  string   `json:"redirect_uri"`
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	Scopes       []string `json:"scopes"`
}
