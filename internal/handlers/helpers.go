package handlers

// ArrayContainsString is a helper to find out if a given string is inside an array or not.
func ArrayContainsString(list []string, key string) bool {
	for _, value := range list {
		if key == value {
			return true
		}
	}
	return false
}
