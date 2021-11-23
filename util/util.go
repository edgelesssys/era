package util

func StringSliceContains(slice []string, str string) bool {
	for _, x := range slice {
		if x == str {
			return true
		}
	}
	return false
}
