package pager

type PasswordGenerator interface {
	HashPassword(password string) string
	ValidatePassword(storedPassword, password string) bool
}

type DefaultBcryptPassword struct{}

func (d *DefaultBcryptPassword) HashPassword(password string) string {
	return hash(password)
}

func (d *DefaultBcryptPassword) ValidatePassword(storedPassword, password string) bool {
	return compareHash(storedPassword, password)
}
