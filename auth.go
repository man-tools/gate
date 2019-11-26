package pager

import (
	"context"
	"errors"
	"github.com/go-redis/redis"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var (
	ErrInvalidPasswordLogin = errors.New("invalid password")
	ErrInvalidUserLogin     = errors.New("invalid user")
	ErrCreatingCookie       = errors.New("error while set cookie")
	ErrInvalidCookie        = errors.New("invalid cookie")
	ErrInvalidAuthorization = errors.New("invalid authorization")
	ErrValidateCookie       = errors.New("error validate cookie")
	ErrUserNotFound         = errors.New("user not found")
	ErrUserNotActive        = errors.New("user is not active")
)

type LoginParams struct {
	Identifier string
	Password   string
}

type LoginMethod int

const (
	LoginEmail         LoginMethod = 0
	LoginUsername      LoginMethod = 1
	LoginEmailUsername LoginMethod = 2

	CookieBasedAuth int = 0
	TokenBasedAuth  int = 1

	authorization string = "Authorization"
	UserPrinciple string = "UserPrinciple"
)

type Auth struct {
	cacheClient      *redis.Client
	loginMethod      LoginMethod
	sessionName      string
	expiredInSeconds int64

	tokenStrategy    TokenGenerator
	passwordStrategy PasswordGenerator
}

func (a *Auth) Authenticate(params LoginParams) (*User, error) {
	var loggedUser *User
	var err error

	switch a.loginMethod {
	case LoginEmail:
		loggedUser, err = FindUser(map[string]interface{}{
			"email": params.Identifier,
		}, nil)
	case LoginUsername:
		loggedUser, err = FindUser(map[string]interface{}{
			"username": params.Identifier,
		}, nil)
	case LoginEmailUsername:
		loggedUser, err = FindUserByUsernameOrEmail(params.Identifier, nil)
	}
	if err != nil {
		return nil, ErrInvalidUserLogin
	}

	if !a.passwordStrategy.ValidatePassword(loggedUser.Password, params.Password) {
		return nil, ErrInvalidPasswordLogin
	}

	if !loggedUser.Active {
		return nil, ErrUserNotActive
	}
	return loggedUser, nil
}

func (a *Auth) SignInWithCookie(w http.ResponseWriter, params LoginParams) (*User, error) {
	loggedUser, err := a.Authenticate(params)
	if err != nil {
		return nil, err
	}

	hashCookie := a.tokenStrategy.GenerateToken()
	http.SetCookie(w, &http.Cookie{
		Name:    a.sessionName,
		Value:   hashCookie,
		Expires: time.Now().Add(time.Duration(a.expiredInSeconds)),
	})

	err = a.cacheClient.Do(
		"SETEX",
		hashCookie,
		strconv.FormatInt(a.expiredInSeconds, 10),
		loggedUser.ID,
	).Err()
	if err != nil {
		return nil, ErrCreatingCookie
	}

	return loggedUser, nil
}

func (a *Auth) SignIn(params LoginParams) (*User, string, error) {
	loggedUser, err := a.Authenticate(params)
	if err != nil {
		return nil, "", err
	}

	token := a.tokenStrategy.GenerateToken()
	err = a.cacheClient.Do(
		"SETEX",
		token,
		strconv.FormatInt(a.expiredInSeconds, 10),
		loggedUser.ID,
	).Err()
	if err != nil {
		return nil, "", ErrCreatingCookie
	}

	return loggedUser, token, nil
}

func (a *Auth) Register(user *User) error {
	user.Password = a.passwordStrategy.HashPassword(user.Password)
	return user.CreateUser()
}

func (a *Auth) ProtectRoute(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, err := a.getUserPrinciple(r, CookieBasedAuth)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), UserPrinciple, user)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}

func (a *Auth) ProtectRouteUsingToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, err := a.getUserPrinciple(r, TokenBasedAuth)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), UserPrinciple, user)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}

func (a *Auth) ProtectWithRBAC(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := GetUserLogin(r)
		if user == nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if !user.CanAccess(r.Method, r.URL.Path) {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (a *Auth) verifyToken(cookie string) (int64, error) {
	result, err := a.cacheClient.Do(
		"GET",
		cookie,
	).Int64()
	if err != nil {
		return -1, err
	}
	return result, nil
}

func (a *Auth) getUserPrinciple(r *http.Request, strategy int) (*User, error) {
	var token string
	switch strategy {
	case CookieBasedAuth:
		cookieData, err := r.Cookie(a.sessionName)
		if err != nil {
			return nil, ErrInvalidCookie
		}
		token = cookieData.Value
	case TokenBasedAuth:
		rawToken := r.Header.Get(authorization)
		headers := strings.Split(rawToken, " ")
		if len(headers) != 2 {
			return nil, ErrInvalidAuthorization
		}
		token = headers[1]
	}

	userID, err := a.verifyToken(token)
	if err != nil {
		return nil, ErrValidateCookie
	}

	user, err := FindUser(map[string]interface{}{
		"id": userID,
	}, nil)
	if err != nil {
		return nil, ErrUserNotFound
	}

	return user, nil
}

func GetUserLogin(r *http.Request) *User {
	ctx := r.Context()
	return ctx.Value(UserPrinciple).(*User)
}
