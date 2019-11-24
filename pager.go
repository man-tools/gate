package pager

import (
	"database/sql"
	"github.com/go-redis/redis"
	"log"
	"sync"
)

type AuthManager interface {
	GenerateToken()
}

// Constants for Error Messaging
const (
	ErrMigration       = "error while migrating rbac-database, reason = %s"
	ErrDialectNotFound = "invalid dialect"
)

const (
	MYSQL_MIGRATION_PATH        = "mysql_migration.sql"
	REVERT_MYSQL_MIGRATION_PATH = "mysql_cleanup_migration.sql"
)

// Constants for TableName
const (
	USER_TABLE            = "rbac_user"
	PERMISSION_TABLE      = "rbac_permission"
	ROLE_TABLE            = "rbac_role"
	ROLE_PERMISSION_TABLE = "rbac_role_permission"
	USER_ROLE_TABLE       = "rbac_user_role"
)

type Pager struct {
	Dialect   string
	Migration *Migration
	Auth      *Auth
}

type SessionOptions struct {
	LoginMethod      LoginMethod
	SessionName      string
	ExpiredInSeconds int64
}
type Options struct {
	DbConnection *sql.DB
	CacheClient  *redis.Client
	Dialect      string
	SchemaName   string
	Session      SessionOptions
}

var dbConnection *sql.DB
var mutexDbLock = &sync.Mutex{}

func setDatabaseConnection(db *sql.DB) {
	mutexDbLock.Lock()
	dbConnection = db
	mutexDbLock.Unlock()
}

type pagerBuilder struct {
	pagerOptions     *Options
	tokenStrategy    TokenGenerator
	passwordStrategy PasswordStrategy
}

func NewPager(opts *Options) *pagerBuilder {
	rbacBuilder := &pagerBuilder{
		pagerOptions: opts,
	}
	defaultTokenGen := &DefaultTokenGenerator{}
	defaultPasswordStrategy := &DefaultBcryptPasswordStrategy{}
	rbacBuilder.tokenStrategy = defaultTokenGen
	rbacBuilder.passwordStrategy = defaultPasswordStrategy
	return rbacBuilder
}

func (p *pagerBuilder) SetTokenGenerator(generator TokenGenerator) *pagerBuilder {
	p.tokenStrategy = generator
	return p
}

func (p *pagerBuilder) SetPasswordStrategy(strategy PasswordStrategy) *pagerBuilder {
	p.passwordStrategy = strategy
	return p
}

func (p *pagerBuilder) BuildPager() *Pager {
	rbac := &Pager{}
	migrator, err := NewMigration(MigrationOptions{
		dialect: p.pagerOptions.Dialect,
		schema:  p.pagerOptions.SchemaName,
	})
	setDatabaseConnection(p.pagerOptions.DbConnection)

	if err != nil {
		log.Fatal(err)
	}

	authModule := &Auth{
		sessionName:      p.pagerOptions.Session.SessionName,
		expiredInSeconds: p.pagerOptions.Session.ExpiredInSeconds,
		loginMethod:      p.pagerOptions.Session.LoginMethod,
		cacheClient:      p.pagerOptions.CacheClient,
		tokenStrategy:    p.tokenStrategy,
		passwordStrategy: p.passwordStrategy,
	}

	rbac.Migration = migrator
	rbac.Auth = authModule
	return rbac
}
