# OpenVPN Okta Authentication Plugin - Copilot Instructions

## Project Overview

This is a **hybrid C/Go security plugin** for OpenVPN Community Edition that authenticates users against Okta's Authentication API with MFA support (TOTP and PUSH). The project builds both a C shared object plugin and a standalone Go binary, targeting Linux systems with strict security requirements.

**Critical Distinction**: This supports OpenVPN Community Edition only, NOT OpenVPN Access Server (OpenVPN-AS).

**Project Statistics**:
- Language: Go 1.25.4 + C
- Files: 19 Go source files (including tests)
- Test Coverage: 97.3%
- License: MPL 2.0
- Module: `gopkg.in/algolia/openvpn-auth-okta.v2`

## Architecture

### Dual-Mode Operation
The plugin operates in two distinct modes with different authentication flows:

1. **Deferred Plugin Mode** (C shared object): OpenVPN loads `openvpn-plugin-auth-okta.so`, which dynamically links to `libokta-auth-validator.so` (Go c-shared library). C plugin extracts environment variables and passes to Go via CGO bridge in `lib/libokta-auth-validator.go`. Results are written to OpenVPN control files.

2. **Script Plugin Mode** (standalone binary): OpenVPN executes `okta-auth-validator` binary directly, passing credentials via environment or temporary files. Results are returned via exit codes.

### Component Boundaries
- **C Layer** (`openvpn-plugin-auth-okta.c`): OpenVPN plugin interface, environment variable extraction, shared library loading via `dlopen/dlsym`
- **CGO Bridge** (`lib/libokta-auth-validator.go`): Exports Go functions to C via `//export` directives, handles struct marshalling between C and Go using embedded C code in comments
- **Validator Core** (`pkg/validator/`): 
  - `validator.go`: Main authentication orchestration (`OktaOpenVPNValidator` struct)
  - `config.go`: Configuration file parsing (INI format via `gopkg.in/ini.v1`)
  - `loading.go`: Credential extraction (via-file and environment methods)
  - `utils.go`: Password parsing, permission checks, logging setup
- **API Client** (`pkg/oktaApiAuth/`):
  - `api.go`: HTTP client, TLS pinning, Okta API requests
  - `oktaApiAuth.go`: MFA verification logic (`Auth()`, `verifyFactors()`, `validateUserMFA()`)
  - `types.go`: Configuration structs (`OktaAPIConfig`, `OktaUserConfig`, `OktaApiAuth`)
  - `api_types.go`: API response structs (all from Okta documentation)
  - `utils.go`: Group validation, factor parsing, pre-checks
- **Binary Entry** (`cmd/okta-auth-validator/main.go`): CLI with comprehensive help text, flag parsing (`-d`, `-dd`, `-deferred`), exit codes

### Security-Critical Patterns

**TLS Certificate Pinning**: The `InitPool()` function in `pkg/oktaApiAuth/api.go` performs mandatory public key pinning. It connects to Okta, extracts peer certificates, computes SHA256 digest of public keys, and validates against `pinset.cfg`. Never bypass or mock this in production code—tests use `gock` to intercept HTTP before TLS.

**Credential Flow**: In deferred mode, credentials never touch disk as environment variables. In script mode via-file, credentials are written to `tmp-dir` which MUST be on tmpfs. See `pkg/validator/loading.go` for credential extraction patterns.

**Control File Permissions**: `pkg/validator/utils.go` contains `checkControlFilePerm()` which validates that control file directories are not group/world writable (security requirement for OpenVPN deferred plugins).

## Build System

The Makefile builds three distinct artifacts with different compilation strategies:

```bash
make binary     # Go binary with -buildmode=pie, static linking, stripped
make plugin     # Both .so files (C plugin + Go c-shared library)
make            # Builds both binary and plugin
```

**Platform-Specific Flags**: CGO is enabled (CGO=1) only on Raspbian for armv7l, disabled elsewhere for static linking. Linux uses `-Wl,-soname` for shared library naming, macOS uses `-Wl,-install_name`.

**Security Compiler Flags**: All builds use `-D_FORTIFY_SOURCE=2 -fstack-protector-strong -Wformat-security` (see `SEC_CFLAGGS` in Makefile).

## Testing Conventions

### Test Structure
Tests use table-driven patterns with `gock` for HTTP mocking. See `pkg/oktaApiAuth/oktaApiAuth_test.go` for the canonical pattern:
- Define test struct (e.g., `authTest`) with test cases including expected requests/responses
- Use helper functions (e.g., `commonAuthTest()`) to iterate test cases
- Mock HTTP with `gock.New(oktaEndpoint)` chaining request/response definitions
- Verify with `assert.False(t, gock.HasUnmatchedRequest())`

**Example Pattern**:
```go
type authTest struct {
    testName      string
    username      string
    password      string
    response      string
    expectedError error
}

tests := []authTest{
    {testName: "Valid TOTP", username: "user@example.com", password: "pass123456", response: readFixture("auth_success.json"), expectedError: nil},
    {testName: "Invalid TOTP", username: "user@example.com", password: "passwrong", response: readFixture("auth_invalid_totp.json"), expectedError: errTOTPFailed},
}

for _, test := range tests {
    t.Run(test.testName, func(t *testing.T) {
        defer gock.Off()
        gock.New(oktaEndpoint).Post("/api/v1/authn").Reply(200).BodyString(test.response)
        // test logic
        assert.False(t, gock.HasUnmatchedRequest())
    })
}
```

### Running Tests
```bash
make test           # Run tests with coverage, generates build/cover.out
make coverage       # Generate build/coverage.html
make badge          # Update README coverage badge (requires gobadge)
```

**Fixture Hygiene**: Tests validate file permissions before running (`chmod -R g-w,o-w testing/fixtures` in Makefile). All JSON fixtures are extracted from actual Okta API documentation.

**Test Organization**:
- `pkg/oktaApiAuth/*_test.go`: API client tests with HTTP mocking
- `pkg/validator/*_test.go`: Validator logic tests (config, loading, utils)
- `testing/fixtures/oktaApi/*.json`: Okta API responses (preauth, auth, groups)
- `testing/fixtures/validator/*.cfg`: Configuration file test cases (valid/invalid formats)

**Coverage Requirements**: Current coverage is 97.3%. Maintain this level when adding new code.

## Configuration Files

- **`config/api.ini.inc`**: Template for production config with all available options documented. Copied to `/etc/okta-auth-validator/api.ini` on install if missing (mode 640 due to API token sensitivity).
- **`config/pinset.cfg`**: TLS certificate pinning configuration. Contains base64-encoded SHA256 public key digests. Updated when Okta rotates certificates.

Configuration is parsed via `gopkg.in/ini.v1` with struct tag validation (see `pkg/validator/config.go`).

## Code Conventions

### File Headers
All Go files MUST include SPDX headers:
```go
// SPDX-FileCopyrightText: 2023-Present Algolia
//
// SPDX-License-Identifier: MPL-2.0
```

### Documentation Standards
**All public functions and types have comprehensive godoc comments** following this format:
- Purpose statement (what it does)
- Detailed behavior explanation (how it works)
- Parameters description (with types and examples)
- Return values explanation (including error cases)
- Security implications (where relevant)
- Usage examples (for complex functions)
- API endpoint references (for Okta API calls)

See `pkg/validator/validator.go` and `pkg/oktaApiAuth/api.go` for canonical examples.

### Logging
Uses `github.com/phuslu/log` with structured logging and UUIDs per authentication session:
```go
log.Info().Msgf("authenticated with %s %s MFA", factor.Provider, factorType)
```
Available levels: TRACE, DEBUG, INFO, WARN, ERROR (set via `api.ini` or validator constructor).

**Session Correlation**: Each authentication attempt gets a UUID that appears in all log messages:
```
Mon Jan 2 15:04:05 2006 [okta-auth-validator:uuid-123](INFO): [user@example.com] authenticated with Okta TOTP MFA
```

### Error Handling
Custom error types in `pkg/oktaApiAuth/api_types.go` for specific Okta failure modes:
- `errPushFailed`, `errTOTPFailed`, `errMFAUnavailable`
- `errMFARequired`, `errUserLocked`, `errPasswordExpired`, `errEnrollNeeded`

Use `parseOktaError()` for smart multi-factor error handling (suppresses non-final factor failures).

### Package Organization
- Public types use alias declarations: `type OktaApiAuth = oktaApiAuth.OktaApiAuth`
- Exported CGO functions use `//export FunctionName` comment directives
- Test helpers in `*_test.go` files (white-box testing)
- All structs have validation tags: `json:"fieldName" validate:"required"`

## Common Development Tasks

### Adding New Configuration Options
1. Update `OktaAPIConfig` struct in `pkg/oktaApiAuth/api_types.go` with struct tags (`json:"fieldName" validate:"required"`)
2. Add to `config/api.ini.inc` with comment documentation
3. Add validation in `pkg/validator/config.go` `readConfigFile()`
4. Add test case in `pkg/validator/config_test.go`

### Adding New MFA Factor Types
1. Define factor verification in `pkg/oktaApiAuth/oktaApiAuth.go` (follow `verifyFactors()` pattern)
2. Add API endpoint handlers in `pkg/oktaApiAuth/api.go`
3. Add test fixtures to `testing/fixtures/oktaApi/` (use actual Okta API responses)
4. Update `doAuthFirstStep()` and `waitForPush()` logic if needed
5. Add error types to `api_types.go` for factor-specific failures

### Writing Comprehensive Godoc Comments
All public functions/types require detailed godoc following these patterns (see enhanced documentation from 2024):

**For Complex Functions** (validator methods, auth flows):
```go
// Authenticate performs the complete authentication flow for an OpenVPN user against Okta.
//
// This method orchestrates the entire authentication process:
// 1. Extracts username/password from OpenVPN environment variables or credential files
// 2. Validates password format (supports appended TOTP codes)
// 3. Calls Okta Authentication API with MFA support
// 4. Writes authentication result to OpenVPN control file (deferred mode only)
//
// Parameters:
//   - uuid: Unique session identifier for log correlation
//   - pluginEnv: OpenVPN plugin environment containing credentials and control file paths
//
// Returns:
//   - bool: true if authentication succeeded, false otherwise
//   - error: nil on success, error details on failure (credential errors, API errors, I/O errors)
//
// Security:
//   - Control file directory permissions are validated before writing
//   - Credentials are never logged or persisted beyond this function scope
//   - Session UUID enables audit trail correlation without exposing sensitive data
func (validator *OktaOpenVPNValidator) Authenticate(uuid string, pluginEnv *PluginEnv) (bool, error) {
```

**For API Functions**:
```go
// InitPool initializes the TLS connection pool with certificate pinning validation.
//
// This function performs mandatory public key pinning to prevent MITM attacks:
// 1. Connects to Okta API endpoint via TLS
// 2. Extracts peer certificates from the connection
// 3. Computes SHA256 digest of each certificate's public key
// 4. Validates at least one digest matches the configured pinset
//
// Security:
//   - NEVER bypass this validation in production environments
//   - Pin updates require manual pinset.cfg modifications
//   - Connection fails if no certificates match the pinset
//
// Okta API Endpoint: https://{oktaEndpoint} (from config)
//
// Returns:
//   - error: nil if pinning validation succeeds, error if connection fails or no pins match
func (okta *OktaApiAuth) InitPool() error {
```

**For Configuration Structs**:
```go
// OktaAPIConfig holds all configuration parameters for Okta API authentication.
//
// This structure is populated from api.ini configuration file and controls:
//   - Okta API endpoint and credentials
//   - TLS certificate pinning configuration
//   - MFA behavior (allowed groups, factor selection)
//   - Logging verbosity and session tracking
//
// Security-Sensitive Fields:
//   - Token: API token with authentication privileges (never log this value)
//   - PinsetFile: Path to certificate pinning configuration (validates TLS connections)
//
// Required Fields (validated by go-playground/validator):
//   - OktaEndpoint, Token, PinsetFile
//
// Optional Fields:
//   - Groups (empty = all users allowed)
//   - LogLevel (defaults to INFO)
//   - UsernameFormat (defaults to email)
type OktaAPIConfig struct {
    OktaEndpoint   string `json:"oktaEndpoint" validate:"required,url"`
    Token          string `json:"token" validate:"required"`
    // ... remaining 9 fields with inline comments
}
```

### Debugging Authentication Flows
Set `LogLevel: TRACE` in `api.ini` to see full request/response bodies. Session IDs (UUID) correlate log lines for single auth attempts. Test with binary directly:
```bash
# Script mode simulation
export username="user@example.com"
export password="pass123456"  # password+TOTP
./build/okta-auth-validator -dd  # double -d for TRACE level
```

### Running Test Suites
```bash
make test           # Run tests with coverage, generates build/cover.out
make coverage       # Generate build/coverage.html
make badge          # Update README coverage badge (requires gobadge)
```

**Adding New Tests**: Follow table-driven pattern with `gock` for HTTP mocking:
```go
func TestNewFeature(t *testing.T) {
    defer gock.Off()
    
    tests := []struct {
        name           string
        expectedError  error
        mockRequest    func()
        mockResponse   string
    }{
        // test cases
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            gock.New(oktaEndpoint).Post("/api/v1/authn").MatchType("json").Reply(200).BodyString(tt.mockResponse)
            // test logic
            assert.False(t, gock.HasUnmatchedRequest())
        })
    }
}
```

## Installation Paths
Default install locations (override with `DESTDIR=/custom/path`):
- Binary: `/usr/bin/okta-auth-validator`
- C Plugin: `/usr/lib/openvpn/plugins/openvpn-plugin-auth-okta.so`
- Go Library: `/usr/lib/libokta-auth-validator.so`
- Config: `/etc/okta-auth-validator/api.ini`, `pinset.cfg`

## Linting
```bash
make lint  # Runs golangci-lint and cppcheck with exhaustive checks
```
Requires `golangci-lint` and `cppcheck` installed separately.

## Recent Enhancements (2024-2025)

### Comprehensive Godoc Documentation
Over 1100 lines of documentation added across all packages:
- **pkg/validator/**: 5 files enhanced with detailed function documentation
  - `validator.go`: OktaOpenVPNValidator struct, New(), Setup(), Authenticate(), WriteControlFile()
  - `loading.go`: PluginEnv struct, loadViaFile(), loadEnvVars()
  - `utils.go`: parsePassword(), checkControlFilePerm(), all utility functions
  - `config.go`: readConfigFile(), loadPinset()
  
- **pkg/oktaApiAuth/**: 5 files enhanced with detailed function and type documentation
  - `types.go`: OktaAPIConfig (11 fields), OktaUserConfig, OktaApiAuth
  - `api_types.go`: ErrorResponse, PreAuthResponse, AuthFactor, AuthResponse, OktaGroups
  - `api.go`: InitPool(), oktaReq(), preAuth(), doAuth(), cancelAuth(), parseAuthResponse(), parseOktaError(), doAuthFirstStep(), waitForPush()
  - `oktaApiAuth.go`: New(), Auth(), verifyFactors(), validateUserMFA()
  - `utils.go`: checkAllowedGroups(), getUserFactors(), preChecks()

### Documentation Patterns Established
All public functions now include:
- Purpose statement (what it does)
- Detailed behavior explanation (how it works, multi-step flows)
- Parameters with types and examples
- Return values with error cases
- Security implications where relevant
- Usage examples for complex functions
- Okta API endpoint references

See `pkg/validator/validator.go` and `pkg/oktaApiAuth/api.go` for canonical examples of comprehensive godoc.
