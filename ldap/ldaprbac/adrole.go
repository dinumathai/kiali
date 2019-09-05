package ldaprbac

import (
	"encoding/csv"
	"strings"
	"sync"

	"github.com/kiali/kiali/config"
	"github.com/kiali/kiali/log"
)

var (
	initADRoleNameFormats sync.Once
	adRoleNameFormats     []*ADRoleNameFormatSpec
)

// ADRoleNameFormatSpec holds the format of an ad-role name as:
// 		<prefix><fieldName1><delimiter><fieldName2>
// For example,
// with prefix "r_k8s_" and delimiter "_", the formatString "r_k8s_appCode_envCode_accessLevel"
// means there are three fields by the name appCode, envCode and accessLevel
// and the string "r_k8s_aaa_eee_rw" when parsed using this formatString will map
//		appCode to "aaa"
//		envCode to "eee"
//		and accessLevel to "rw"
type ADRoleNameFormatSpec struct {
	Prefix       string         `json:"prefix"`
	Delimiter    rune           `json:"delimiter"`
	FormatString string         `json:"formatString"`
	FieldIndex   map[string]int `json:"-"`
}

const (
	appCodeFieldName = "appCode"
	envCodeFieldName = "envCode"
)

// NewADRoleNameFormatSpec creates a new ADRoleNameFormatSpec
func NewADRoleNameFormatSpec(prefix string, delim rune, formatString string) *ADRoleNameFormatSpec {
	fieldIndex := make(map[string]int)

	if !strings.HasPrefix(formatString, prefix) {
		return nil
	}

	// Skip the prefix and take rest of the string
	formatString = formatString[len(prefix):]

	r := csv.NewReader(strings.NewReader(formatString))
	r.Comma = delim // Use delimitter as the 'comma'

	// Split all the fields
	fields, err := r.Read()
	if err != nil {
		return nil
	}

	// Map the field names to their index
	for i, field := range fields {
		fieldIndex[field] = i
	}

	return &ADRoleNameFormatSpec{
		Prefix:       prefix,
		Delimiter:    delim,
		FormatString: formatString,
		FieldIndex:   fieldIndex,
	}
}

// ParseFieldsFromADRoleName parses a string adRoleName using the given format specification
// See the notes on ADRoleNameFormatSpec for details on the specification
func ParseFieldsFromADRoleName(spec *ADRoleNameFormatSpec, adRoleName string) map[string]string {
	if spec == nil || !strings.HasPrefix(adRoleName, spec.Prefix) {
		return nil
	}

	// Skip the prefix and take rest of the string
	adRoleData := adRoleName[len(spec.Prefix):]

	r := csv.NewReader(strings.NewReader(adRoleData))
	r.Comma = spec.Delimiter // Use delimitter as the 'comma'

	// Split all the fields
	fields, err := r.Read()
	if err != nil {
		return nil
	}

	fieldData := make(map[string]string)
	for name, index := range spec.FieldIndex {
		if index >= len(fields) { // If there is a format mismatch index can go out of range
			return nil
		}
		fieldData[name] = fields[index]
	}

	return fieldData
}

// GetADRoleNameFormats returns the ad-role name format specs
// The first time GetADRoleNameFormats is called, it loads the formats from the
// config file
func GetADRoleNameFormats() []*ADRoleNameFormatSpec {
	initADRoleNameFormats.Do(func() {
		// Load the configuration
		conf := config.Get()
		for entryIndex, formatCfg := range conf.Auth.LDAP.LdapRbac.ADRoleNameFormats {
			isValidCfg := true

			// Check for ambiguity with existing configuration
			for _, nameFmt := range adRoleNameFormats {
				if strings.HasPrefix(nameFmt.Prefix, formatCfg.Prefix) || strings.HasPrefix(formatCfg.Prefix, nameFmt.Prefix) {
					isValidCfg = false
					log.Debugf("AD Role Name Format - ambiguous prefixes: '%s' and '%s'. Skipping configuration #%d", nameFmt.Prefix, formatCfg.Prefix, entryIndex)
					break
				}

				if len(formatCfg.Delimiter) != 1 {
					isValidCfg = false
					log.Debugf("AD Role Name Format - invalid delimiter. Skipping configuration #%d", entryIndex)
					break
				}
			}

			if isValidCfg {
				adRoleNameFormats = append(adRoleNameFormats, NewADRoleNameFormatSpec(formatCfg.Prefix, rune(formatCfg.Delimiter[0]), formatCfg.FormatString))
			}
		}
	})

	return adRoleNameFormats
}
