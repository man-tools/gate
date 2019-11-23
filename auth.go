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
	UserPrinciple      string      = "UserPrinciple"
	CookieBasedAuth    int         = 0
	TokenBasedAuth     int         = 1
)

type Auth struct {
	cacheClient      *redis.Client
	loginMethod      LoginMethod
	sessionName      string
	expiredInSeconds int64
}

func (a *Auth) SignInHttp(w http.ResponseWriter, params LoginParams) (*User, error) {
	var user *User
	var err error

	switch a.loginMethod {
	case LoginEmail:
		user, err = FindUser(map[string]interface{}{
			"email": params.Identifier,
		})
	case LoginUsername:
		user, err = FindUser(map[string]interface{}{
			"username": params.Identifier,
		})
	case LoginEmailUsername:
		user, err = FindUserByUsernameOrEmail(params.Identifier)
	}
	if err != nil {
		return nil, ErrInvalidUserLogin
	}

	if !compareHash(user.Password, params.Password) {
		return nil, ErrInvalidPasswordLogin
	}

	// set cookie
	hashCookie := getRandomHash()
	http.SetCookie(w, &http.Cookie{
		Name:    a.sessionName,
		Value:   hashCookie,
		Expires: time.Now().Add(time.Duration(a.expiredInSeconds)),
	})

	// save to redis
	err = a.cacheClient.Do(
		"SETEX",
		hashCookie,
		strconv.FormatInt(a.expiredInSeconds, 10),
		user.ID,
	).Err()
	if err != nil {
		return nil, ErrCreatingCookie
	}

	return user, nil
}

func (a *Auth) SignIn(params LoginParams) (*User, string, error) {
	var user *User
	var err error

	switch a.loginMethod {
	case LoginEmail:
		user, err = FindUser(map[string]interface{}{
			"email": params.Identifier,
		})
	case LoginUsername:
		user, err = FindUser(map[string]interface{}{
			"username": params.Identifier,
		})
	case LoginEmailUsername:
		user, err = FindUserByUsernameOrEmail(params.Identifier)
	}
	if err != nil {
		return nil, "", ErrInvalidUserLogin
	}

	if !compareHash(user.Password, params.Password) {
		return nil, "", ErrInvalidPasswordLogin
	}

	// set cookie
	token := getRandomHash()

	// save to redis
	err = a.cacheClient.Do(
		"SETEX",
		token,
		strconv.FormatInt(a.expiredInSeconds, 10),
		user.ID,
	).Err()
	if err != nil {
		return nil, "", ErrCreatingCookie
	}

	return user, token, nil
}

func (a *Auth) Register(user *User) error {
	passwordHash := hash(user.Password)
	user.Password = passwordHash
	return user.CreateUser()
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

func (a *Auth) GetUserPrinciple(r *http.Request, strategy int) (*User, error) {
	var token string
	switch strategy {
	case CookieBasedAuth:
		cookieData, err := r.Cookie(a.sessionName)
		if err != nil {
			return nil, ErrInvalidCookie
		}
		token = cookieData.Value
	case TokenBasedAuth:
		rawToken := r.Header.Get("Authorization")
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
	})
	if err != nil {
		return nil, ErrUserNotFound
	}

	return user, nil
}

func (a *Auth) ProtectRoute(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, err := a.GetUserPrinciple(r, CookieBasedAuth)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), UserPrinciple, user)
		r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}

func (a *Auth) ProtectRouteUsingToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, err := a.GetUserPrinciple(r, TokenBasedAuth)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), UserPrinciple, user)
		r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}

func (a *Auth) ProtectWithRBAC(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		ctx := r.Context()
		user := ctx.Value(UserPrinciple).(*User)
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
