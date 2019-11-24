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

func NewConnection(opts *Options) *Pager {
	rbac := &Pager{}

	setDatabaseConnection(opts.DbConnection)

	migrator, err := NewMigration(MigrationOptions{
		dialect: opts.Dialect,
		schema:  opts.SchemaName,
	})

	if err != nil {
		log.Fatal(err)
	}

	defaultTokenGen := &DefaultTokenGenerator{}
	defaultPasswordStrategy := &DefaultBcryptPasswordStrategy{}

	authModule := &Auth{
		sessionName:      opts.Session.SessionName,
		expiredInSeconds: opts.Session.ExpiredInSeconds,
		loginMethod:      opts.Session.LoginMethod,
		cacheClient:      opts.CacheClient,
		tokenStrategy:    defaultTokenGen,
		passwordStrategy: defaultPasswordStrategy,
	}

	rbac.Migration = migrator
	rbac.Auth = authModule
	return rbac
}

func (p *Pager) SetTokenGenerator(generator TokenGenerator) {
	p.Auth.tokenStrategy = generator
}

func (p *Pager) SetPasswordStrategy(strategy PasswordStrategy) {
	p.Auth.passwordStrategy = strategy
}
