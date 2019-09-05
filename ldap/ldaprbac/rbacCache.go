package ldaprbac

import (
	"github.com/kiali/kiali/log"
)

var (
	roleToAppMap map[string][]*RoleToAppMapping
)

// accessConfigurationFromCache provides the data for RBAC check from internal cache
type accessConfigurationFromCache struct{}

func (c *accessConfigurationFromCache) AppsForRole(role string) []*RoleToAppMapping {
	return roleToAppMap[role]
}

//Refresh the RBAC Cached Data
func refreshLdapRBACCache() error {
	log.Debugf("Refreshing the cache of RBAC : START")

	err := loadRBACCacheData()
	if err != nil {
		log.Debugf("Refreshing the cache of RBAC : FAILED\n%v", err)
		return err
	}

	log.Debugf("Refreshing the cache of RBAC : SUCCESS")
	return nil
}

func loadRBACCacheData() error {
	roleToAppMapTemp := make(map[string][]*RoleToAppMapping)

	// Load role to app code mapping
	// Current source is only DB more can me added
	roleToAppList, err := getRoleToAppMappingMysqlDB()
	if err != nil {
		return err
	}

	for i, item := range roleToAppList {
		if appList, exists := roleToAppMapTemp[item.Role]; exists {
			roleToAppMapTemp[item.Role] = append(appList, &roleToAppList[i])
		} else {
			roleToAppMapTemp[item.Role] = []*RoleToAppMapping{&roleToAppList[i]}
		}
	}

	roleToAppMap = roleToAppMapTemp

	return nil
}
