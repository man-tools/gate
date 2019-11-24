package pager

type TokenGenerator interface {
	GenerateToken() string
	GenerateCookie() string
}

type DefaultTokenGenerator struct {
}

func (d *DefaultTokenGenerator) GenerateToken() string {
	return getRandomHash()
}

func (d *DefaultTokenGenerator) GenerateCookie() string {
	return getRandomHash()
}
