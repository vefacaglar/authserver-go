package domain

import "time"

type User struct {
	ID                   string
	Username             string
	Email                string
	EmailConfirmed       bool
	PhoneNumber          string
	PhoneNumberConfirmed bool
	PasswordHash         string
	SecurityStamp        string
	TwoFactorEnabled     bool
	LockoutEnd           *time.Time
	LockoutEnabled       bool
	AccessFailedCount    int
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

type UserClaim struct {
	Type  string
	Value string
}

type Role struct {
	ID   string
	Name string
}

type RoleClaim struct {
	Type  string
	Value string
}

type UserLogin struct {
	LoginProvider string
	ProviderKey   string
	ProviderName  string
	UserID        string
}

type UserToken struct {
	UserID        string
	LoginProvider string
	Name          string
	Value         string
}
