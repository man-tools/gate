package pager

import (
	uuid "github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
)

func hash(str string) string {
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(str), 10)
	return string(hashedPassword)
}

func compareHash(storedPassword, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(password))
	return err == nil
}

func getRandomHash() string {
	randomUUID := uuid.NewV4()
	return hash(randomUUID.String())
}
