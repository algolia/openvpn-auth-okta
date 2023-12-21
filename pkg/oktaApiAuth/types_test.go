package oktaApiAuth

// used in api_test.go
type poolTest struct {
	testName string
	host     string
	port     string
	pinset   []string
	err      error
}

// used in api_test.go
type setupTest struct {
	testName string
	requests []authRequest
	err      error
}

// used in oktaApiAuth_test.go
type authTest struct {
	testName      string
	mfaRequired   bool
	passcode      string
	requests      []authRequest
	unmatchedReq  bool
	allowedGroups string
	err           error
}

// used in api_test.go, oktaApiAuth_test.go, utils_test.go
type authRequest struct {
	path             string
	payload          map[string]string
	httpStatus       int
	jsonResponseFile string
}

// used in utils_test.go
type allowedGroupsTest struct {
	testName      string
	requests      []authRequest
	allowedGroups string
	err           error
}
