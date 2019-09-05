package ldaprbac

// ContainsExact looks up a string in a slice in a case sensitive way
func ContainsExact(stringSlice []string, compareItem string) bool {
	for _, item := range stringSlice {
		if item == compareItem {
			return true
		}
	}
	return false
}
