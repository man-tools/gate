package pager

import "database/sql"

type PagerTx struct {
	dbTx *sql.Tx
}

func (ptx *PagerTx) BeginTx() error {
	tx, err := dbConnection.Begin()
	ptx.dbTx = tx
	return err
}

func (ptx *PagerTx) User(user *User) *User {
	user.db = ptx.dbTx
	return user
}

func (ptx *PagerTx) Role(role *Role) *Role {
	role.db = ptx.dbTx
	return role
}

func (ptx *PagerTx) Permission(permission *Permission) *Permission {
	permission.db = ptx.dbTx
	return permission
}

func (ptx *PagerTx) FinishTx(err error) error {
	if err == nil {
		return ptx.dbTx.Commit()
	}
	return ptx.dbTx.Rollback()
}
