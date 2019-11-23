package pager

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

var (
	ErrInvalidUserID       = errors.New("invalid user id")
	ErrInvalidPermissionID = errors.New("invalid permission id")
	ErrInvalidRoleID       = errors.New("invalid role id")
)

// User Repository
type User struct {
	ID       int64  `db:"id" json:"id"`
	Username string `db:"username" json:"username"`
	Email    string `db:"email" json:"email"`
	Password string `db:"password" json:"-"`
	Active   bool   `db:"active" json:"active"`
	Roles    []Role `db:"-"`
}

func (u *User) CreateUser() error {
	insertQuery := `INSERT INTO rbac_user (
		email, 
		username,
		password) VALUES (?,?,?)`
	result, err := dbConnection.Exec(
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
	saveQuery := `INSERT INTO rbac_user (
		email,
		username,
		password,
		active
	) VALUES(?, ?, ?, ?) ON DUPLICATE KEY UPDATE email = ?, username = ?, password = ?, active = ?`

	result, err := dbConnection.Exec(
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
	if u.ID <= 0 {
		return ErrInvalidUserID
	}

	deleteQuery := `DELETE FROM rbac_user WHERE id = ?`

	_, err := dbConnection.Exec(
		deleteQuery,
		u.ID,
	)
	if err != nil {
		return err
	}
	return nil
}

func (u *User) CanAccess(method, path string) bool {
	getQuery := `SELECT 
		COUNT(1) as count
	FROM rbac_user_role ur 
	JOIN rbac_role_permission rp ON ur.role_id = rp.role_id
	JOIN rbac_permission p ON p.id = rp. permission_id 
	WHERE ur.user_id = ? AND p.method = ? AND p.route = ?`

	rowData := struct {
		count int64 `db:"count"`
	}{}

	result := dbConnection.QueryRow(getQuery, u.ID, method, path)
	err := result.Scan(&rowData.count)
	if err != nil {
		return false
	}
	return rowData.count > 0
}

func (u *User) HasPermission(permissionName string) bool {
	getQuery := `SELECT 
		COUNT(1) as count
	FROM rbac_user_role ur 
	JOIN rbac_role_permission rp ON ur.role_id = rp.role_id
	JOIN rbac_permission p ON p.id = rp. permission_id 
	WHERE ur.user_id = ? AND p.name = ?`

	rowData := struct {
		count int64 `db:"count"`
	}{}

	result := dbConnection.QueryRow(getQuery, u.ID, permissionName)
	err := result.Scan(&rowData.count)
	if err != nil {
		return false
	}
	return rowData.count > 0
}

func (u *User) HasRole(roleName string) bool {
	getQuery := `SELECT 
		COUNT(1) as count
	FROM rbac_user_role ur 
	JOIN rbac_role r ON ur.role_id = r.id 
	WHERE ur.user_id = ? AND r.name = ?`

	rowData := struct {
		count int64 `db:"count"`
	}{}

	result := dbConnection.QueryRow(getQuery, u.ID, roleName)
	err := result.Scan(&rowData.count)
	if err != nil {
		return false
	}
	return rowData.count > 0
}

func (u *User) fetchRole() ([]Role, error) {
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
	result, err := dbConnection.Query(getQuery, u.ID)
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

func GetUser(email string) (*User, error) {
	var user = new(User)
	getQuery := `SELECT id, email, username, password, active FROM rbac_user WHERE email = ?`

	result := dbConnection.QueryRow(getQuery, email)
	err := result.Scan(&user.ID, &user.Email, &user.Username, &user.Password, &user.Active)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	// fetch existing roles
	roles, err := user.fetchRole()
	if err != nil {
		return nil, err
	}

	user.Roles = roles
	return user, nil
}

func FindUserByUsernameOrEmail(params string) (*User, error) {
	var user = new(User)
	getQuery := `SELECT id, email, username, password, active FROM rbac_user WHERE email = ? OR username = ?`

	result := dbConnection.QueryRow(getQuery, params, params)
	err := result.Scan(&user.ID, &user.Email, &user.Username, &user.Password, &user.Active)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	// fetch existing roles
	roles, err := user.fetchRole()
	if err != nil {
		return nil, err
	}

	user.Roles = roles
	return user, nil
}

func FindUser(params map[string]interface{}) (*User, error) {
	var user = new(User)
	var result *sql.Row
	paramsLength := len(params)

	getQuery := `SELECT id, email, username, password, active FROM rbac_user WHERE `

	values := make([]interface{}, 0)
	index := 0
	for k := range params {
		getQuery += fmt.Sprintf("%s = ?", k)
		if index < paramsLength-1 {
			getQuery += `,`
		}
		values = append(values, params[k])
	}

	result = dbConnection.QueryRow(getQuery, values...)
	err := result.Scan(&user.ID, &user.Email, &user.Username, &user.Password, &user.Active)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	// fetch existing roles
	roles, err := user.fetchRole()
	if err != nil {
		return nil, err
	}

	user.Roles = roles
	return user, nil

}

// Role Repository
type Role struct {
	ID          int64     `db:"id" json:"id"`
	Name        string    `db:"name" json:"name"`
	Description string    `db:"description" json:"description"`
	CreatedAt   time.Time `db:"created_at" json:"created_at"`
	UpdatedAt   time.Time `db:"updated_at" json:"updated_at"`
	Permission  []Permission
}

func (r *Role) CreateRole() error {
	insertQuery := `INSERT INTO rbac_role (
		name, 
		description) VALUES (?,?)`
	result, err := dbConnection.Exec(
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
	if r.ID <= 0 {
		return ErrInvalidRoleID
	}
	deleteQuery := `DELETE FROM rbac_role WHERE id = ?`
	_, err := dbConnection.Exec(
		deleteQuery,
		r.ID,
	)
	if err != nil {
		return err
	}
	return nil
}

func (r *Role) Assign(u *User) error {
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
	_, err := dbConnection.Exec(
		insertQuery,
		r.ID,
		u.ID,
	)
	if err != nil {
		return err
	}

	u.Roles = append(u.Roles, *r)
	return nil
}

func (r *Role) Revoke(u *User) error {
	if r.ID <= 0 {
		return ErrInvalidRoleID
	}

	if u.ID <= 0 {
		return ErrInvalidUserID
	}

	revokeQuery := `DELETE FROM rbac_user_role WHERE role_id = ? AND user_id = ?`
	_, err := dbConnection.Exec(
		revokeQuery,
		r.ID,
		u.ID,
	)
	if err != nil {
		return err
	}

	for i := range u.Roles {
		if u.Roles[i].ID == r.ID {
			u.Roles = append(u.Roles[:i], u.Roles[i+1:]...)
		}
	}

	return nil
}

func (r *Role) AddChild(p *Permission) error {
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
	_, err := dbConnection.Exec(
		insertQuery,
		r.ID,
		p.ID,
	)
	if err != nil {
		return err
	}
	r.Permission = append(r.Permission, *p)
	return nil
}

func (r *Role) RemoveChild(p *Permission) error {
	if r.ID <= 0 {
		return ErrInvalidRoleID
	}

	if p.ID <= 0 {
		return ErrInvalidPermissionID
	}

	revokeQuery := `DELETE FROM rbac_role_permission WHERE role_id = ? AND permission_id = ?`
	_, err := dbConnection.Exec(
		revokeQuery,
		r.ID,
		p.ID,
	)
	if err != nil {
		return err
	}

	for i := range r.Permission {
		if r.Permission[i].ID == p.ID {
			r.Permission = append(r.Permission[:i], r.Permission[i+1:]...)
		}
	}

	return nil
}

func GetRole(name string) (*Role, error) {
	var role = new(Role)
	getQuery := `SELECT
		id,
		name,
		description,
		created_at,
		updated_at
	FROM rbac_role WHERE name = ?`

	result := dbConnection.QueryRow(getQuery, name)
	err := result.Scan(&role.ID, &role.Name, &role.Description, &role.CreatedAt, &role.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return role, nil
}

func getRoleByID(id int64) (*Role, error) {
	var role = new(Role)
	getQuery := `SELECT
		id,
		name,
		description,
		created_at,
		updated_at
	FROM rbac_role WHERE id = ?`

	result := dbConnection.QueryRow(getQuery, id)
	err := result.Scan(role)
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
	ID          int64     `db:"id"`
	Name        string    `db:"name"`
	Method      string    `db:"method"`
	Route       string    `db:"route"`
	Description string    `db:"description"`
	CreatedAt   time.Time `db:"created_at"`
	UpdatedAt   time.Time `db:"updated_at"`
}

func (p *Permission) CreatePermission() error {
	insertQuery := `INSERT INTO rbac_permission (
		name, 
		method,
		route,
		description) VALUES (?,?,?,?)`
	result, err := dbConnection.Exec(
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
	if p.ID <= 0 {
		return ErrInvalidPermissionID
	}
	deleteQuery := `DELETE FROM rbac_permission WHERE id = ?`
	_, err := dbConnection.Exec(
		deleteQuery,
		p.ID,
	)
	if err != nil {
		return err
	}
	return nil
}

func GetPermission(name string) (*Permission, error) {
	var permission = new(Permission)
	getQuery := `SELECT
		id,
		name,
		method,
		route,
		description,
		created_at,
		updated_at
	FROM rbac_permission WHERE name = ?`

	result := dbConnection.QueryRow(getQuery, name)
	err := result.Scan(&permission.ID, &permission.Name, &permission.Method, &permission.Route, &permission.Description, &permission.CreatedAt, &permission.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return permission, nil
}
