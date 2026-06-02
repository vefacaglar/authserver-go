package domain

type Scope struct {
	Name        string
	DisplayName string
	Description string
	Required    bool
	Emphasize   bool
	Properties  map[string]string
}
