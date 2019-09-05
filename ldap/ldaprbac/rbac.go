package ldaprbac

import (
	"fmt"
	"github.com/kiali/kiali/ldap"
	"github.com/kiali/kiali/models"
	"strings"
)

// ApplicationRBACObject represents the object on which access control needs to
// be applied in telemetry.
// The primary object on which access control is to be applied is an application
// in an environment
type ApplicationRBACObject struct {
	AppCode  string
	EnvCodes []string
}

type ApplicationRBACObjectMap map[string]*ApplicationRBACObject

var (
	accessConfig AccessConfigurationProvider
)

func SetAccessConfigurationProvider(c AccessConfigurationProvider) {
	accessConfig = c
}

func (o *ApplicationRBACObject) String() string {

	switch {
	case len(o.AppCode) > 0 && len(o.EnvCodes) > 0:
		return fmt.Sprintf("%s(%v)", o.AppCode, o.EnvCodes)

	case len(o.AppCode) > 0:
		return o.AppCode

	case len(o.EnvCodes) > 0:
		return fmt.Sprintf("unknown(%v)", o.EnvCodes)
	}

	return "(nil)"
}

// NewApplicationRBACObject constructs a ApplicationRBACObject
func NewApplicationRBACObject(appCode string, envCodes []string) *ApplicationRBACObject {
	object := new(ApplicationRBACObject)
	object.AppCode = appCode
	object.EnvCodes = envCodes

	return object
}

// NewApplicationRBACObjectsFromKubeNamespace is to create an app object from namespace
func NewApplicationRBACObjectFromKubeNamespace(namespace string) *ApplicationRBACObject {
	var appObj *ApplicationRBACObject
	values := strings.SplitN(namespace, "-", 3)
	if len(values) < 2 {
		return appObj
	}
	appCode := values[0]
	envCode := values[1]
	appObj = NewApplicationRBACObject(appCode, []string{envCode})
	return appObj
}

type AccessChecker interface {
	IsNameSpaceAllowed(namespace string) (bool, error)
	FilterNameSpaces(namespace []models.Namespace) []models.Namespace
}

func GetAccessChecker(user *ldap.User) AccessChecker {
	checker := &rbacAccessChecker{
		user:           user,
		allowedAppsMap: nil, // Keep it nil to check for initialization
		isAdmin:        false,
	}

	return checker
}

// IsApplicationAllowed checks if the given user has access to the application in the
// given environment
func (checker *rbacAccessChecker) IsApplicationAllowed(object *ApplicationRBACObject) (bool, error) {
	if err := checker.loadAllAllowedApplications(); err != nil {
		return false, err
	}

	if _, exists := checker.allowedAppsMap["*"]; exists {
		return true, nil
	}

	if object == nil {
		return false, nil
	}

	if allowedApp, exists := checker.allowedAppsMap[object.AppCode]; exists { // Check application requested
		for _, envCode := range object.EnvCodes { // Check all environments requested
			if ContainsExact(allowedApp.EnvCodes, "*") {
				return true, nil
			}

			if !ContainsExact(allowedApp.EnvCodes, envCode) {
				return false, nil
			}
		}
		return true, nil
	}

	return false, nil
}

func (checker *rbacAccessChecker) FilterNameSpaces(namespaceList []models.Namespace) []models.Namespace {
	filteredNamespaces := []models.Namespace{}
	for _, namespace := range namespaceList {
		if isAllowed, err := checker.IsNameSpaceAllowed(namespace.Name); isAllowed && err == nil {
			filteredNamespaces = append(filteredNamespaces, namespace)
		}
	}

	return filteredNamespaces
}

func (checker *rbacAccessChecker) IsNameSpaceAllowed(namespace string) (bool, error) {
	if namespace == "" {
		return false, nil
	}
	appObj := NewApplicationRBACObjectFromKubeNamespace(namespace)
	return checker.IsApplicationAllowed(appObj)
}

func (checker *rbacAccessChecker) getAppsForRole(roleName string) []*RoleToAppMapping {
	var appsForRole []*RoleToAppMapping

	for _, spec := range GetADRoleNameFormats() {
		if strings.HasPrefix(roleName, spec.Prefix) {
			fieldMap := ParseFieldsFromADRoleName(spec, roleName)
			if fieldMap != nil {
				app := RoleToAppMapping{
					Role:    roleName,
					AppCode: fieldMap[appCodeFieldName],
					EnvCode: fieldMap[envCodeFieldName],
				}

				appsForRole = append(appsForRole, &app)
			}
		}
	}

	// Apps configured for user group
	appsForRoleByConfig := accessConfig.AppsForRole(roleName)
	if len(appsForRoleByConfig) > 0 {
		appsForRole = append(appsForRole, appsForRoleByConfig...)
	}

	return appsForRole
}

func (checker *rbacAccessChecker) loadAllAllowedApplications() error {
	if checker.allowedAppsMap != nil { // Already loaded
		return nil
	}

	objectMap := make(map[string]*ApplicationRBACObject)

	for _, userGroup := range checker.user.Groups {
		appsForRole := checker.getAppsForRole(userGroup)

		for _, app := range appsForRole {
			if app.AppCode == "*" { // special case - allow all apps
				object := NewApplicationRBACObject(app.AppCode, nil)
				objectMap[app.AppCode] = object
			}
			if object, exists := objectMap[app.AppCode]; exists {
				// If all envs are allowed, no need to add any specific env
				if ContainsExact(object.EnvCodes, "*") {
					continue
				}

				// If this is an allow-all case, remove all other environments
				if app.EnvCode == "*" {
					object.EnvCodes = []string{"*"}
				}

				if !ContainsExact(object.EnvCodes, app.EnvCode) {
					object.EnvCodes = append(object.EnvCodes, app.EnvCode)
				}
			} else {
				object := NewApplicationRBACObject(app.AppCode, []string{app.EnvCode})
				objectMap[app.AppCode] = object
			}
		}
	}

	checker.allowedAppsMap = objectMap

	return nil
}
