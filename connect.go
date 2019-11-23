package pager

import (
	"database/sql"
	"github.com/go-redis/redis"
	"log"
)

// Connection interface is an abstraction for connecting db
type Connection interface {
	ConnectDatabase(connectionString string)
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
}

type Options struct {
	DbConnection *sql.DB
	TokenSource  *redis.Client
	Dialect      string
	SchemaName   string
}

var dbConnection *sql.DB

func NewConnection(opts *Options) *Pager {
	rbac := &Pager{}

	dbConnection = opts.DbConnection

	// init migration
	migrator, err := NewMigration(MigrationOptions{
		dialect: opts.Dialect,
		schema:  opts.SchemaName,
	})

	if err != nil {
		log.Fatal(err)
	}

	rbac.Migration = migrator
	return rbac
}
