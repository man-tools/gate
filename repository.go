package pager

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

var (
	ErrInvalidUserID       = errors.New("invalid user id")
	ErrInvalidPermissionID = errors.New("invalid permission id")
	ErrInvalidRoleID       = errors.New("invalid role id")
	ErrTxWithNoBegin       = errors.New("error dbTx without begin()")
)

type dbContract interface {
	Prepare(query string) (*sql.Stmt, error)
	PrepareContext(ctx context.Context, query string) (*sql.Stmt, error)
	Query(query string, args ...interface{}) (*sql.Rows, error)
	QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error)
	QueryRow(query string, args ...interface{}) *sql.Row
	QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row
	Exec(query string, args ...interface{}) (sql.Result, error)
	ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error)
}

// User Repository
type User struct {
	ID       int64  `db:"id" json:"id"`
	Username string `db:"username" json:"username"`
	Email    string `db:"email" json:"email"`
	Password string `db:"password" json:"-"`
	Active   bool   `db:"active" json:"active"`

	db dbContract
}

func (u *User) CreateUser() error {
	if u.db == nil {
		u.db = dbConnection
	}
	insertQuery := `INSERT INTO rbac_user (
		email, 
		username,
		password) VALUES (?,?,?)`

	result, err := u.db.Exec(
		insertQuery,
		u.Email,
		u.Username,
		u.Password,
	)

	if err != nil {
		return err
	}

	u.ID, err = result.LastInsertId()
	u.Active = true
	return nil
}

func (u *User) CreateUserWithContext(ctx context.Context) error {
	if u.db == nil {
		u.db = dbConnection
	}
	insertQuery := `INSERT INTO rbac_user (
		email, 
		username,
		password) VALUES (?,?,?)`

	result, err := u.db.ExecContext(
		ctx,
		insertQuery,
		u.Email,
		u.Username,
		u.Password,
	)

	if err != nil {
		return err
	}

	u.ID, err = result.LastInsertId()
	u.Active = true
	return nil
}

func (u *User) Save() error {
	if u.db == nil {
		u.db = dbConnection
	}
	saveQuery := `INSERT INTO rbac_user (
		email,
		username,
		password,
		active
	) VALUES(?, ?, ?, ?) ON DUPLICATE KEY UPDATE email = ?, username = ?, password = ?, active = ?`

	result, err := u.db.Exec(
		saveQuery,
		u.Email,
		u.Username,
		u.Password,
		u.Active,
		u.Email,
		u.Username,
		u.Password,
		u.Active,
	)
	if err != nil {
		return err
	}

	u.ID, _ = result.LastInsertId()
	return nil
}

func (u *User) SaveWithContext(ctx context.Context) error {
	if u.db == nil {
		u.db = dbConnection
	}
	saveQuery := `INSERT INTO rbac_user (
		email,
		username,
		password,
		active
	) VALUES(?, ?, ?, ?) ON DUPLICATE KEY UPDATE email = ?, username = ?, password = ?, active = ?`

	result, err := u.db.ExecContext(
		ctx,
		saveQuery,
		u.Email,
		u.Username,
		u.Password,
		u.Active,
		u.Email,
		u.Username,
		u.Password,
		u.Active,
	)
	if err != nil {
		return err
	}

	u.ID, _ = result.LastInsertId()
	return nil
}

func (u *User) Delete() error {
	if u.db == nil {
		u.db = dbConnection
	}
	if u.ID <= 0 {
		return ErrInvalidUserID
	}

	deleteQuery := `DELETE FROM rbac_user WHERE id = ?`

	_, err := u.db.Exec(
		deleteQuery,
		u.ID,
	)
	if err != nil {
		return err
	}
	return nil
}

func (u *User) DeleteWithContext(ctx context.Context) error {
	if u.db == nil {
		u.db = dbConnection
	}
	if u.ID <= 0 {
		return ErrInvalidUserID
	}

	deleteQuery := `DELETE FROM rbac_user WHERE id = ?`

	_, err := u.db.ExecContext(
		ctx,
		deleteQuery,
		u.ID,
	)
	if err != nil {
		return err
	}
	return nil
}

func (u *User) CanAccess(method, path string) bool {
	if u.db == nil {
		u.db = dbConnection
	}
	getQuery := `SELECT 
		COUNT(1) as count
	FROM rbac_user_role ur 
	JOIN rbac_role_permission rp ON ur.role_id = rp.role_id
	JOIN rbac_permission p ON p.id = rp. permission_id 
	WHERE ur.user_id = ? AND p.method = ? AND p.route = ?`

	rowData := struct {
		count int64 `db:"count"`
	}{}

	result := u.db.QueryRow(getQuery, u.ID, method, path)
	err := result.Scan(&rowData.count)
	if err != nil {
		return false
	}
	return rowData.count > 0
}

func (u *User) CanAccessWithContext(ctx context.Context, method, path string) bool {
	if u.db == nil {
		u.db = dbConnection
	}
	getQuery := `SELECT 
		COUNT(1) as count
	FROM rbac_user_role ur 
	JOIN rbac_role_permission rp ON ur.role_id = rp.role_id
	JOIN rbac_permission p ON p.id = rp. permission_id 
	WHERE ur.user_id = ? AND p.method = ? AND p.route = ?`

	rowData := struct {
		count int64 `db:"count"`
	}{}

	result := u.db.QueryRowContext(ctx, getQuery, u.ID, method, path)
	err := result.Scan(&rowData.count)
	if err != nil {
		return false
	}
	return rowData.count > 0
}

func (u *User) HasPermission(permissionName string) bool {
	if u.db == nil {
		u.db = dbConnection
	}
	getQuery := `SELECT 
		COUNT(1) as count
	FROM rbac_user_role ur 
	JOIN rbac_role_permission rp ON ur.role_id = rp.role_id
	JOIN rbac_permission p ON p.id = rp. permission_id 
	WHERE ur.user_id = ? AND p.name = ?`

	rowData := struct {
		count int64 `db:"count"`
	}{}

	result := u.db.QueryRow(getQuery, u.ID, permissionName)
	err := result.Scan(&rowData.count)
	if err != nil {
		return false
	}
	return rowData.count > 0
}

func (u *User) HasPermissionWithContext(ctx context.Context, permissionName string) bool {
	if u.db == nil {
		u.db = dbConnection
	}
	getQuery := `SELECT 
		COUNT(1) as count
	FROM rbac_user_role ur 
	JOIN rbac_role_permission rp ON ur.role_id = rp.role_id
	JOIN rbac_permission p ON p.id = rp. permission_id 
	WHERE ur.user_id = ? AND p.name = ?`

	rowData := struct {
		count int64 `db:"count"`
	}{}

	result := u.db.QueryRowContext(ctx, getQuery, u.ID, permissionName)
	err := result.Scan(&rowData.count)
	if err != nil {
		return false
	}
	return rowData.count > 0
}

func (u *User) HasRole(roleName string) bool {
	if u.db == nil {
		u.db = dbConnection
	}
	getQuery := `SELECT 
		COUNT(1) as count
	FROM rbac_user_role ur 
	JOIN rbac_role r ON ur.role_id = r.id 
	WHERE ur.user_id = ? AND r.name = ?`

	rowData := struct {
		count int64 `db:"count"`
	}{}

	result := u.db.QueryRow(getQuery, u.ID, roleName)
	err := result.Scan(&rowData.count)
	if err != nil {
		return false
	}
	return rowData.count > 0
}

func (u *User) HasRoleWithContext(ctx context.Context, roleName string) bool {
	if u.db == nil {
		u.db = dbConnection
	}
	getQuery := `SELECT 
		COUNT(1) as count
	FROM rbac_user_role ur 
	JOIN rbac_role r ON ur.role_id = r.id 
	WHERE ur.user_id = ? AND r.name = ?`

	rowData := struct {
		count int64 `db:"count"`
	}{}

	result := u.db.QueryRowContext(ctx, getQuery, u.ID, roleName)
	err := result.Scan(&rowData.count)
	if err != nil {
		return false
	}
	return rowData.count > 0
}

func (u *User) GetRoles() ([]Role, error) {
	if u.db == nil {
		u.db = dbConnection
	}
	var roles []Role
	getQuery := `SELECT
		r.id,
		r.name,
		r.description,
		r.created_at,
		r.updated_at
	FROM rbac_user_role ur
	JOIN rbac_role r WHERE ur.user_id = ?`

	roles = make([]Role, 0)
	result, err := u.db.Query(getQuery, u.ID)
	if err != nil {
		if err == sql.ErrNoRows {
			return roles, nil
		}
		return nil, err
	}

	var role Role
	for result.Next() {
		err = result.Scan(&role)
		if err == nil {
			roles = append(roles, role)
		}
	}
	return roles, nil
}

func (u *User) GetRolesWithContext(ctx context.Context) ([]Role, error) {
	if u.db == nil {
		u.db = dbConnection
	}
	var roles []Role
	getQuery := `SELECT
		r.id,
		r.name,
		r.description,
		r.created_at,
		r.updated_at
	FROM rbac_user_role ur
	JOIN rbac_role r WHERE ur.user_id = ?`

	roles = make([]Role, 0)
	result, err := u.db.QueryContext(ctx, getQuery, u.ID)
	if err != nil {
		if err == sql.ErrNoRows {
			return roles, nil
		}
		return nil, err
	}

	var role Role
	for result.Next() {
		err = result.Scan(&role)
		if err == nil {
			roles = append(roles, role)
		}
	}
	return roles, nil
}

func GetUser(email string, ptx *PagerTx) (*User, error) {
	var db dbContract
	if ptx == nil {
		db = dbConnection
	} else {
		if ptx.dbTx == nil {
			return nil, ErrTxWithNoBegin
		}
		db = ptx.dbTx
	}

	var user = new(User)
	getQuery := `SELECT id, email, username, password, active FROM rbac_user WHERE email = ?`

	result := db.QueryRow(getQuery, email)
	err := result.Scan(&user.ID, &user.Email, &user.Username, &user.Password, &user.Active)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return user, nil
}

func GetUserWithContext(ctx context.Context, email string, ptx *PagerTx) (*User, error) {
	var db dbContract
	if ptx == nil {
		db = dbConnection
	} else {
		if ptx.dbTx == nil {
			return nil, ErrTxWithNoBegin
		}
		db = ptx.dbTx
	}

	var user = new(User)
	getQuery := `SELECT id, email, username, password, active FROM rbac_user WHERE email = ?`

	result := db.QueryRowContext(ctx, getQuery, email)
	err := result.Scan(&user.ID, &user.Email, &user.Username, &user.Password, &user.Active)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return user, nil
}

func FindUserByUsernameOrEmail(params string, ptx *PagerTx) (*User, error) {
	var db dbContract
	if ptx == nil {
		db = dbConnection
	} else {
		if ptx.dbTx == nil {
			return nil, ErrTxWithNoBegin
		}
		db = ptx.dbTx
	}

	var user = new(User)
	getQuery := `SELECT id, email, username, password, active FROM rbac_user WHERE email = ? OR username = ?`

	result := db.QueryRow(getQuery, params, params)
	err := result.Scan(&user.ID, &user.Email, &user.Username, &user.Password, &user.Active)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return user, nil
}

func FindUserByUsernameOrEmailWithContext(ctx context.Context, params string, ptx *PagerTx) (*User, error) {
	var db dbContract
	if ptx == nil {
		db = dbConnection
	} else {
		if ptx.dbTx == nil {
			return nil, ErrTxWithNoBegin
		}
		db = ptx.dbTx
	}

	var user = new(User)
	getQuery := `SELECT id, email, username, password, active FROM rbac_user WHERE email = ? OR username = ?`

	result := db.QueryRowContext(ctx, getQuery, params, params)
	err := result.Scan(&user.ID, &user.Email, &user.Username, &user.Password, &user.Active)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return user, nil
}

func FindUser(params map[string]interface{}, ptx *PagerTx) (*User, error) {
	var db dbContract
	if ptx == nil {
		db = dbConnection
	} else {
		if ptx.dbTx == nil {
			return nil, ErrTxWithNoBegin
		}
		db = ptx.dbTx
	}
	var user = new(User)
	var result *sql.Row
	paramsLength := len(params)

	getQuery := `SELECT id, email, username, password, active FROM rbac_user WHERE `

	values := make([]interface{}, 0)
	index := 0
	for k := range params {
		getQuery += fmt.Sprintf("%s = ?", k)
		if index < paramsLength-1 {
			getQuery += ` AND `
		}
		values = append(values, params[k])
	}

	result = db.QueryRow(getQuery, values...)
	err := result.Scan(&user.ID, &user.Email, &user.Username, &user.Password, &user.Active)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return user, nil

}

func FindUserWithContext(ctx context.Context, params map[string]interface{}, ptx *PagerTx) (*User, error) {
	var db dbContract
	if ptx == nil {
		db = dbConnection
	} else {
		if ptx.dbTx == nil {
			return nil, ErrTxWithNoBegin
		}
		db = ptx.dbTx
	}
	var user = new(User)
	var result *sql.Row
	paramsLength := len(params)

	getQuery := `SELECT id, email, username, password, active FROM rbac_user WHERE `

	values := make([]interface{}, 0)
	index := 0
	for k := range params {
		getQuery += fmt.Sprintf("%s = ?", k)
		if index < paramsLength-1 {
			getQuery += ` AND `
		}
		values = append(values, params[k])
	}

	result = db.QueryRowContext(ctx, getQuery, values...)
	err := result.Scan(&user.ID, &user.Email, &user.Username, &user.Password, &user.Active)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return user, nil

}

// Role Repository
type Role struct {
	ID          int64  `db:"id" json:"id"`
	Name        string `db:"name" json:"name"`
	Description string `db:"description" json:"description"`

	db dbContract
}

func (r *Role) CreateRole() error {
	if r.db == nil {
		r.db = dbConnection
	}

	insertQuery := `INSERT INTO rbac_role (
		name, 
		description) VALUES (?,?)`
	result, err := r.db.Exec(
		insertQuery,
		r.Name,
		r.Description,
	)
	if err != nil {
		return err
	}

	r.ID, _ = result.LastInsertId()
	return nil
}

func (r *Role) CreateRoleWithContext(ctx context.Context) error {
	if r.db == nil {
		r.db = dbConnection
	}

	insertQuery := `INSERT INTO rbac_role (
		name, 
		description) VALUES (?,?)`
	result, err := r.db.ExecContext(
		ctx,
		insertQuery,
		r.Name,
		r.Description,
	)
	if err != nil {
		return err
	}

	r.ID, _ = result.LastInsertId()
	return nil
}

func (r *Role) DeleteRole() error {
	if r.db == nil {
		r.db = dbConnection
	}

	if r.ID <= 0 {
		return ErrInvalidRoleID
	}
	deleteQuery := `DELETE FROM rbac_role WHERE id = ?`
	_, err := r.db.Exec(
		deleteQuery,
		r.ID,
	)
	if err != nil {
		return err
	}
	return nil
}

func (r *Role) DeleteRoleWithContext(ctx context.Context) error {
	if r.db == nil {
		r.db = dbConnection
	}

	if r.ID <= 0 {
		return ErrInvalidRoleID
	}
	deleteQuery := `DELETE FROM rbac_role WHERE id = ?`
	_, err := r.db.ExecContext(
		ctx,
		deleteQuery,
		r.ID,
	)
	if err != nil {
		return err
	}
	return nil
}

func (r *Role) Assign(u *User) error {
	if r.db == nil {
		r.db = dbConnection
	}
	if r.ID <= 0 {
		return ErrInvalidRoleID
	}

	if u.ID <= 0 {
		return ErrInvalidUserID
	}

	insertQuery := `INSERT INTO rbac_user_role (
		role_id, 
		user_id
	) VALUES (?,?)`
	_, err := r.db.Exec(
		insertQuery,
		r.ID,
		u.ID,
	)
	if err != nil {
		return err
	}
	return nil
}

func (r *Role) AssignWithContext(ctx context.Context, u *User) error {
	if r.db == nil {
		r.db = dbConnection
	}
	if r.ID <= 0 {
		return ErrInvalidRoleID
	}

	if u.ID <= 0 {
		return ErrInvalidUserID
	}

	insertQuery := `INSERT INTO rbac_user_role (
		role_id, 
		user_id
	) VALUES (?,?)`
	_, err := r.db.ExecContext(
		ctx,
		insertQuery,
		r.ID,
		u.ID,
	)
	if err != nil {
		return err
	}
	return nil
}

func (r *Role) Revoke(u *User) error {
	if r.db == nil {
		r.db = dbConnection
	}

	if r.ID <= 0 {
		return ErrInvalidRoleID
	}

	if u.ID <= 0 {
		return ErrInvalidUserID
	}

	revokeQuery := `DELETE FROM rbac_user_role WHERE role_id = ? AND user_id = ?`
	_, err := r.db.Exec(
		revokeQuery,
		r.ID,
		u.ID,
	)
	if err != nil {
		return err
	}

	return nil
}

func (r *Role) RevokeWithContext(ctx context.Context, u *User) error {
	if r.db == nil {
		r.db = dbConnection
	}

	if r.ID <= 0 {
		return ErrInvalidRoleID
	}

	if u.ID <= 0 {
		return ErrInvalidUserID
	}

	revokeQuery := `DELETE FROM rbac_user_role WHERE role_id = ? AND user_id = ?`
	_, err := r.db.ExecContext(
		ctx,
		revokeQuery,
		r.ID,
		u.ID,
	)
	if err != nil {
		return err
	}

	return nil
}

func (r *Role) AddChild(p *Permission) error {
	if r.db == nil {
		r.db = dbConnection
	}

	if r.ID <= 0 {
		return ErrInvalidRoleID
	}

	if p.ID <= 0 {
		return ErrInvalidPermissionID
	}

	insertQuery := `INSERT INTO rbac_role_permission (
		role_id, 
		permission_id
	) VALUES (?,?)`
	_, err := r.db.Exec(
		insertQuery,
		r.ID,
		p.ID,
	)
	if err != nil {
		return err
	}
	return nil
}

func (r *Role) AddChildWithContext(ctx context.Context, p *Permission) error {
	if r.db == nil {
		r.db = dbConnection
	}

	if r.ID <= 0 {
		return ErrInvalidRoleID
	}

	if p.ID <= 0 {
		return ErrInvalidPermissionID
	}

	insertQuery := `INSERT INTO rbac_role_permission (
		role_id, 
		permission_id
	) VALUES (?,?)`
	_, err := r.db.ExecContext(
		ctx,
		insertQuery,
		r.ID,
		p.ID,
	)
	if err != nil {
		return err
	}
	return nil
}

func (r *Role) RemoveChild(p *Permission) error {
	if r.db == nil {
		r.db = dbConnection
	}

	if r.ID <= 0 {
		return ErrInvalidRoleID
	}

	if p.ID <= 0 {
		return ErrInvalidPermissionID
	}

	revokeQuery := `DELETE FROM rbac_role_permission WHERE role_id = ? AND permission_id = ?`
	_, err := r.db.Exec(
		revokeQuery,
		r.ID,
		p.ID,
	)
	if err != nil {
		return err
	}
	return nil
}

func (r *Role) RemoveChildWithContext(ctx context.Context, p *Permission) error {
	if r.db == nil {
		r.db = dbConnection
	}

	if r.ID <= 0 {
		return ErrInvalidRoleID
	}

	if p.ID <= 0 {
		return ErrInvalidPermissionID
	}

	revokeQuery := `DELETE FROM rbac_role_permission WHERE role_id = ? AND permission_id = ?`
	_, err := r.db.ExecContext(
		ctx,
		revokeQuery,
		r.ID,
		p.ID,
	)
	if err != nil {
		return err
	}
	return nil
}

func (r *Role) GetPermission() ([]Permission, error) {
	if r.db == nil {
		r.db = dbConnection
	}
	var permissions []Permission
	getQuery := `SELECT
		p.id,
		p.name,
		p.method,
		p.route,
		p.description
	FROM rbac_role_permission rp
	JOIN rbac_permission p WHERE rp.role_id = ?`

	permissions = make([]Permission, 0)
	result, err := r.db.Query(getQuery, r.ID)
	if err != nil {
		if err == sql.ErrNoRows {
			return permissions, nil
		}
		return nil, err
	}

	var permission Permission
	for result.Next() {
		err = result.Scan(&permission.ID, &permission.Name, &permission.Method, &permission.Route, &permission.Description)
		if err == nil {
			permissions = append(permissions, permission)
		}
	}
	return permissions, nil
}

func (r *Role) GetPermissionWithContext(ctx context.Context) ([]Permission, error) {
	if r.db == nil {
		r.db = dbConnection
	}
	var permissions []Permission
	getQuery := `SELECT
		p.id,
		p.name,
		p.method,
		p.route,
		p.description
	FROM rbac_role_permission rp
	JOIN rbac_permission p WHERE rp.role_id = ?`

	permissions = make([]Permission, 0)
	result, err := r.db.QueryContext(ctx, getQuery, r.ID)
	if err != nil {
		if err == sql.ErrNoRows {
			return permissions, nil
		}
		return nil, err
	}

	var permission Permission
	for result.Next() {
		err = result.Scan(&permission.ID, &permission.Name, &permission.Method, &permission.Route, &permission.Description)
		if err == nil {
			permissions = append(permissions, permission)
		}
	}
	return permissions, nil
}

func GetRole(name string, ptx *PagerTx) (*Role, error) {
	var db dbContract
	if ptx == nil {
		db = dbConnection
	} else {
		if ptx.dbTx == nil {
			return nil, ErrTxWithNoBegin
		}
		db = ptx.dbTx
	}
	var role = new(Role)
	getQuery := `SELECT
		id,
		name,
		description 
	FROM rbac_role WHERE name = ?`

	result := db.QueryRow(getQuery, name)
	err := result.Scan(&role.ID, &role.Name, &role.Description)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return role, nil
}

func GetRoleContext(ctx context.Context, name string, ptx *PagerTx) (*Role, error) {
	var db dbContract
	if ptx == nil {
		db = dbConnection
	} else {
		if ptx.dbTx == nil {
			return nil, ErrTxWithNoBegin
		}
		db = ptx.dbTx
	}
	var role = new(Role)
	getQuery := `SELECT
		id,
		name,
		description 
	FROM rbac_role WHERE name = ?`

	result := db.QueryRowContext(ctx, getQuery, name)
	err := result.Scan(&role.ID, &role.Name, &role.Description)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return role, nil
}

// Permission Repository
type Permission struct {
	ID          int64  `db:"id"`
	Name        string `db:"name"`
	Method      string `db:"method"`
	Route       string `db:"route"`
	Description string `db:"description"`

	db dbContract
}

func (p *Permission) CreatePermission() error {
	if p.db == nil {
		p.db = dbConnection
	}
	insertQuery := `INSERT INTO rbac_permission (
		name, 
		method,
		route,
		description) VALUES (?,?,?,?)`
	result, err := p.db.Exec(
		insertQuery,
		p.Name,
		p.Method,
		p.Route,
		p.Description,
	)
	if err != nil {
		return err
	}

	p.ID, _ = result.LastInsertId()
	return nil
}

func (p *Permission) CreatePermissionWithContext(ctx context.Context) error {
	if p.db == nil {
		p.db = dbConnection
	}
	insertQuery := `INSERT INTO rbac_permission (
		name, 
		method,
		route,
		description) VALUES (?,?,?,?)`
	result, err := p.db.ExecContext(
		ctx,
		insertQuery,
		p.Name,
		p.Method,
		p.Route,
		p.Description,
	)
	if err != nil {
		return err
	}

	p.ID, _ = result.LastInsertId()
	return nil
}

func (p *Permission) DeletePermission() error {
	if p.db == nil {
		p.db = dbConnection
	}
	if p.ID <= 0 {
		return ErrInvalidPermissionID
	}
	deleteQuery := `DELETE FROM rbac_permission WHERE id = ?`
	_, err := p.db.Exec(
		deleteQuery,
		p.ID,
	)
	if err != nil {
		return err
	}
	return nil
}

func (p *Permission) DeletePermissionWithContext(ctx context.Context) error {
	if p.db == nil {
		p.db = dbConnection
	}
	if p.ID <= 0 {
		return ErrInvalidPermissionID
	}
	deleteQuery := `DELETE FROM rbac_permission WHERE id = ?`
	_, err := p.db.ExecContext(
		ctx,
		deleteQuery,
		p.ID,
	)
	if err != nil {
		return err
	}
	return nil
}

func GetPermission(name string, ptx *PagerTx) (*Permission, error) {
	var db dbContract
	if ptx == nil {
		db = dbConnection
	} else {
		if ptx.dbTx == nil {
			return nil, ErrTxWithNoBegin
		}
		db = ptx.dbTx
	}

	var permission = new(Permission)
	getQuery := `SELECT
		id,
		name,
		method,
		route,
		description
	FROM rbac_permission WHERE name = ?`

	result := db.QueryRow(getQuery, name)
	err := result.Scan(&permission.ID, &permission.Name, &permission.Method, &permission.Route, &permission.Description)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return permission, nil
}

func GetPermissionWithContext(ctx context.Context, name string, ptx *PagerTx) (*Permission, error) {
	var db dbContract
	if ptx == nil {
		db = dbConnection
	} else {
		if ptx.dbTx == nil {
			return nil, ErrTxWithNoBegin
		}
		db = ptx.dbTx
	}

	var permission = new(Permission)
	getQuery := `SELECT
		id,
		name,
		method,
		route,
		description
	FROM rbac_permission WHERE name = ?`

	result := db.QueryRowContext(ctx, getQuery, name)
	err := result.Scan(&permission.ID, &permission.Name, &permission.Method, &permission.Route, &permission.Description)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return permission, nil
}

// Group Repository
type Group struct {
	ID   int64  `db:"id"`
	Name string `db:"name"`

	db dbContract
}

func (g *Group) CreateGroup() error {
	if g.db == nil {
		g.db = dbConnection
	}
	insertQuery := `INSERT INTO rbac_group (
		name
	) VALUES (?)`
	result, err := g.db.Exec(
		insertQuery,
		g.Name,
	)
	if err != nil {
		return err
	}

	g.ID, _ = result.LastInsertId()
	return nil
}

func (g *Group) CreateGroupWithContext(ctx context.Context) error {
	if g.db == nil {
		g.db = dbConnection
	}
	insertQuery := `INSERT INTO rbac_group (
		name
	) VALUES (?)`
	result, err := g.db.ExecContext(
		ctx,
		insertQuery,
		g.Name,
	)
	if err != nil {
		return err
	}

	g.ID, _ = result.LastInsertId()
	return nil
}

func (g *Group) DeleteGroup() error {
	if g.db == nil {
		g.db = dbConnection
	}
	if g.ID <= 0 {
		return ErrInvalidPermissionID
	}
	deleteQuery := `DELETE FROM rbac_group WHERE id = ?`
	_, err := g.db.Exec(
		deleteQuery,
		g.ID,
	)
	if err != nil {
		return err
	}
	return nil
}

func (g *Group) DeleteGroupWithContext(ctx context.Context) error {
	if g.db == nil {
		g.db = dbConnection
	}
	if g.ID <= 0 {
		return ErrInvalidPermissionID
	}
	deleteQuery := `DELETE FROM rbac_group WHERE id = ?`
	_, err := g.db.ExecContext(
		ctx,
		deleteQuery,
		g.ID,
	)
	if err != nil {
		return err
	}
	return nil
}

func (g *Group) GetUsers(page, size int64) ([]User, error) {
	var user User
	var err error
	users := make([]User, 0)

	var offset int64
	if page <= 1 {
		offset = 0
	} else {
		offset = page * size
	}

	getQuery := `SELECT 
		u.id, 
		u.email, 
		u.username, 
		u.password, 
		u.active 
	FROM rbac_user_group g 
	JOIN rbac_user u ON g.user_id = u.id 
	WHERE g.group_id = ? 
	LIMIT ? OFFSET ?`

	result, err := g.db.Query(getQuery, g.ID, size, offset)

	for result.Next() {
		err = result.Scan(
			&user.ID,
			&user.Email,
			&user.Username,
			&user.Password,
			&user.Active,
		)
		if err != nil {
			if err == sql.ErrNoRows {
				return nil, nil
			}
			return nil, err
		}

		users = append(users, user)
	}

	return users, nil
}

func (g *Group) GetUsersWithContext(ctx context.Context, page, size int64) ([]User, error) {
	var user User
	var err error
	users := make([]User, 0)

	var offset int64
	if page <= 1 {
		offset = 0
	} else {
		offset = page * size
	}

	getQuery := `SELECT 
		u.id, 
		u.email, 
		u.username, 
		u.password, 
		u.active 
	FROM rbac_user_group g 
	JOIN rbac_user u ON g.user_id = u.id 
	WHERE g.group_id = ? 
	LIMIT ? OFFSET ?`

	result, err := g.db.QueryContext(ctx, getQuery, g.ID, size, offset)

	for result.Next() {
		err = result.Scan(
			&user.ID,
			&user.Email,
			&user.Username,
			&user.Password,
			&user.Active,
		)
		if err != nil {
			if err == sql.ErrNoRows {
				return nil, nil
			}
			return nil, err
		}

		users = append(users, user)
	}

	return users, nil
}

func GetGroup(name string, ptx *PagerTx) (*Group, error) {
	var db dbContract
	if ptx == nil {
		db = dbConnection
	} else {
		if ptx.dbTx == nil {
			return nil, ErrTxWithNoBegin
		}
		db = ptx.dbTx
	}

	var group = new(Group)
	getQuery := `SELECT
		id,
		name
	FROM rbac_group WHERE name = ?`

	result := db.QueryRow(getQuery, name)
	err := result.Scan(&group.ID, &group.Name)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return group, nil
}

func GetGroupWithContext(ctx context.Context, name string, ptx *PagerTx) (*Group, error) {
	var db dbContract
	if ptx == nil {
		db = dbConnection
	} else {
		if ptx.dbTx == nil {
			return nil, ErrTxWithNoBegin
		}
		db = ptx.dbTx
	}

	var group = new(Group)
	getQuery := `SELECT
		id,
		name
	FROM rbac_group WHERE name = ?`

	result := db.QueryRowContext(ctx, getQuery, name)
	err := result.Scan(&group.ID, &group.Name)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return group, nil
}

// Migration Repository
func checkExistMigration(ptx *PagerTx, migrationType string) (bool, error) {
	rawResult := struct {
		MigrationKey string `db:"migration_key"`
	}{}
	selectQuery := `SELECT migration_key FROM rbac_migration WHERE migration_key = ? LIMIT 1`
	result := ptx.dbTx.QueryRow(selectQuery, migrationType)
	err := result.Scan(&rawResult)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func insertMigration(ptx *PagerTx, migrationType string) error {
	insertQuery := `INSERT INTO rbac_migration(migration_key) VALUES (?)`
	_, err := ptx.dbTx.Exec(
		insertQuery,
		migrationType,
	)
	return err
}
