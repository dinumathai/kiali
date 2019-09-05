package ldaprbac

import (
	"github.com/kiali/kiali/ldap"
)

type RoleToAppMapping struct {
	ID      int    `db:"rbac_role_to_app_mapping_id"`
	Role    string `db:"role"`
	AppCode string `db:"app_code"`
	EnvCode string `db:"env_code"`
}

// UserContext stores the RBAC context for a user
type rbacAccessChecker struct {
	user           *ldap.User
	allowedAppsMap ApplicationRBACObjectMap
	isAdmin        bool
}

// AccessConfigurationProvider provides the RBAC configuration data
type AccessConfigurationProvider interface {
	AppsForRole(role string) []*RoleToAppMapping
}
