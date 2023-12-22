package oktaApiAuth

// Computed with:
/*
echo -n | openssl s_client -connect example.oktapreview.com:443 2>/dev/null |\
 openssl x509 -noout -pubkey |\
 openssl rsa	-pubin -outform der 2>/dev/null |\
 openssl dgst -sha256 -binary | base64
*/
// used in api_test.go, oktaApiAuth_test.go, utils_test.go
var pin []string = []string{"SE4qe2vdD9tAegPwO79rMnZyhHvqj3i5g1c2HkyGUNE="}


// used in api_test.go, oktaApiAuth_test.go, utils_test.go
type authRequest struct {
	path             string
	payload          map[string]string
	httpStatus       int
	jsonResponseFile string
}
