package pager

type PasswordStrategy interface {
	HashPassword(password string) string
	ValidatePassword(storedPassword, password string) bool
}

type DefaultBcryptPasswordStrategy struct{}

func (d *DefaultBcryptPasswordStrategy) HashPassword(password string) string {
	return hash(password)
}

func (d *DefaultBcryptPasswordStrategy) ValidatePassword(storedPassword, password string) bool {
	return compareHash(storedPassword, password)
}
