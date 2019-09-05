package ldaprbac

import (
	"database/sql"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gocraft/dbr"
	"github.com/kiali/kiali/config"
	"github.com/kiali/kiali/log"
)

var db *sql.DB

const (
	maxConnection            = 2
	idleConnetion            = 1
	getRoleToAppMappingQuery = `SELECT rbac_role_to_app_mapping_id, role, app_code, env_code FROM rbac_role_to_app_mapping`
)

// RDS DB Connection Initialize
func DBConnectionInitialize() (*sql.DB, error) {
	if db == nil {
		conf := config.Get()
		var connString string = conf.Auth.LDAP.LdapRbac.DBConnString
		var err error
		db, err = sql.Open("mysql", connString)
		if err != nil {
			log.Warningf("Unable to Connect to DB", err)
			return nil, err
		}
		db.SetMaxOpenConns(maxConnection)
		db.SetMaxOpenConns(idleConnetion)
		err = db.Ping()
		if err != nil {
			log.Warningf("Unable to Open DBConnection %v", err)
			return nil, err
		}
	}
	return db, nil
}

func getRoleToAppMappingMysqlDB() ([]RoleToAppMapping, error) {
	var roleAppMap []RoleToAppMapping

	dbconn, err := DBConnectionInitialize()
	if err != nil {
		return roleAppMap, err
	}

	rows, err := dbconn.Query(getRoleToAppMappingQuery)
	if err != nil {
		log.Debugf("Unable to execute query %s \n %v", getRoleToAppMappingQuery, err)
		return nil, err
	}
	defer rows.Close()

	_, err = dbr.Load(rows, &roleAppMap)
	if err != nil {
		log.Debugf("Unable to Map to app table struct %v", err)
		return nil, err
	}

	return roleAppMap, nil
}
