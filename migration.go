package pager

import (
	"database/sql"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"reflect"
	"runtime"
	"strings"
)

const (
	MYSQLDialect       = "mysql"
	delimiterMigration = ";"
)

var (
	ErrMigrationAlreadyExist = errors.New("error while running migration, migration already exist")
)

type RunMigration interface {
	Run(ptx *PagerTx) error
}

type indexSchema struct {
	TableName string `db:"table_name"`
	IndexName string `db:"index_name"`
}

var existTable = map[string]bool{
	USER_TABLE:            false,
	PERMISSION_TABLE:      false,
	ROLE_TABLE:            false,
	ROLE_PERMISSION_TABLE: false,
	USER_ROLE_TABLE:       false,
	MIGRATION:             false,
}
var indexes = map[string]string{
	"rbac_user_email_idx":                      "CREATE UNIQUE INDEX `rbac_user_email_idx` ON rbac_user(email)",
	"rbac_user_username_idx":                   "CREATE UNIQUE INDEX `rbac_user_username_idx` ON rbac_user(username)",
	"rbac_permission_route_method_idx":         "CREATE UNIQUE INDEX `rbac_permission_route_method_idx` ON rbac_permission(route, method)",
	"rbac_permission_name_idx":                 "CREATE UNIQUE INDEX `rbac_permission_name_idx` ON rbac_permission(name)",
	"rbac_role_name_idx":                       "CREATE UNIQUE INDEX `rbac_role_name_idx` ON rbac_role(name)",
	"rbac_user_role_role_user_idx":             "CREATE UNIQUE INDEX `rbac_user_role_role_user_idx` on rbac_user_role (role_id, user_id)",
	"rbac_role_permission_role_permission_idx": "CREATE UNIQUE INDEX `rbac_role_permission_role_permission_idx` on rbac_role_permission (role_id, permission_id)",
	"rbac_migration_key_idx":                   "CREATE UNIQUE INDEX `rbac_migration_key_idx` on rbac_migration (migration_key)",
}

type defaultMigrationConfig struct {
	migrationPath       string
	revertMigrationPath string
}

type Migration struct {
	dialect    string
	schemaName string
	config     defaultMigrationConfig
}

type MigrationOptions struct {
	DBConnection *sql.DB
	dialect      string
	schema       string
}

var queryCollection = map[string]defaultMigrationConfig{
	MYSQLDialect: {
		migrationPath:       MYSQL_MIGRATION_PATH,
		revertMigrationPath: REVERT_MYSQL_MIGRATION_PATH,
	},
}

func NewMigration(opts MigrationOptions) (*Migration, error) {
	dc, ok := queryCollection[opts.dialect]
	if !ok {
		return nil, errors.New(ErrDialectNotFound)
	}

	m := &Migration{
		dialect:    opts.dialect,
		config:     dc,
		schemaName: opts.schema,
	}
	return m, nil
}

func (m *Migration) InitDBMigration() error {
	rawMigrationQuery, err := openMigration(fmt.Sprintf("%s/migration/%s", getCurrentPath(), MYSQL_MIGRATION_PATH))
	if err != nil {
		return errors.New(fmt.Sprintf(ErrMigration, "failed to open migration file"))
	}

	sliceQuery := strings.Split(rawMigrationQuery, delimiterMigration)
	for i := range sliceQuery {
		if len(strings.TrimSpace(sliceQuery[i])) == 0 {
			continue
		}
		_, err = dbConnection.Exec(sliceQuery[i])
		if err != nil {
			log.Println(err)
			m.ClearMigration()
			return errors.New(fmt.Sprintf(ErrMigration, "failed to execute query"))
		}
	}
	err = m.migrateIndexes()
	if err != nil {
		log.Println(err)
		m.ClearMigration()
		return errors.New(fmt.Sprintf(ErrMigration, "failed to execute query"))
	}
	return nil
}

func (m *Migration) ClearMigration() {
	fmt.Println("clear rbac-db")
	rawMigrationQuery, _ := openMigration(fmt.Sprintf("%s/migration/%s", getCurrentPath(), REVERT_MYSQL_MIGRATION_PATH))

	sliceQuery := strings.Split(rawMigrationQuery, delimiterMigration)
	for i := range sliceQuery {
		if len(strings.TrimSpace(sliceQuery[i])) == 0 {
			continue
		}
		_, err := dbConnection.Exec(sliceQuery[i])
		if err != nil {
			log.Println(err)
		}
	}
}

func (m *Migration) CheckMigration() error {
	var err error
	rows, err := dbConnection.Query("SHOW TABLES")
	if err != nil {
		log.Println(err)
		return errors.New(fmt.Sprintf(ErrMigration, "error while checking the tables"))
	}

	var tableName string
	for rows.Next() {
		err = rows.Scan(&tableName)
		if err != nil {
			log.Println(err)
			return errors.New(fmt.Sprintf(ErrMigration, "error while checking the tables"))
		}

		if _, ok := existTable[tableName]; ok {
			existTable[tableName] = true
		}
	}

	for k := range existTable {
		if !existTable[k] {
			return errors.New(fmt.Sprintf(ErrMigration, "table doesn't exist"))
		}
	}
	return nil
}

func (m *Migration) Run(migration RunMigration) error {
	var err error
	ptx := &PagerTx{}

	err = ptx.BeginTx()
	if err != nil {
		return err
	}
	defer ptx.FinishTx(err)

	alreadyRun, err := checkExistMigration(ptx, reflect.TypeOf(migration).String())
	if err != nil {
		return err
	}
	if alreadyRun {
		err = ErrMigrationAlreadyExist
		return ErrMigrationAlreadyExist
	}
	err = migration.Run(ptx)
	return nil
}

func (m *Migration) migrateIndexes() error {
	querySchema := `SELECT DISTINCT 
		TABLE_NAME AS table_name,
		INDEX_NAME AS index_name 
	FROM INFORMATION_SCHEMA.STATISTICS 
	WHERE TABLE_SCHEMA = ? 
	AND INDEX_NAME <> ?`

	rows, err := dbConnection.Query(querySchema, m.schemaName, "PRIMARY")
	if err != nil {
		log.Println(err)
		return errors.New(fmt.Sprintf(ErrMigration, "error while checking the tables"))
	}

	var index indexSchema
	for rows.Next() {
		err = rows.Scan(&index.TableName, &index.IndexName)
		if err != nil {
			log.Println(err)
			return errors.New(fmt.Sprintf(ErrMigration, "error while checking the tables"))
		}

		if _, ok := indexes[index.IndexName]; ok {
			delete(indexes, index.IndexName)
		}
	}

	for k := range indexes {
		if len(strings.TrimSpace(indexes[k])) == 0 {
			continue
		}
		_, err = dbConnection.Exec(indexes[k])
		if err != nil {
			log.Println(err)
			m.ClearMigration()
			return errors.New(fmt.Sprintf(ErrMigration, "failed to execute query"))
		}
	}
	return nil
}

func getCurrentPath() string {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		return ""
	}

	return path.Dir(filename)
}

func openMigration(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	b, err := ioutil.ReadAll(file)
	if err != nil {
		return "", err
	}

	return string(b), nil
}
