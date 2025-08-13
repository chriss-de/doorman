# doorman [![PkgGoDev](https://pkg.go.dev/badge/github.com/chriss-de/doorman)](https://pkg.go.dev/github.com/chriss-de/doorman) [![Go Report Card](https://goreportcard.com/badge/github.com/chriss-de/doorman)](https://goreportcard.com/report/github.com/chriss-de/doorman)

Doorman can protect your REST API or other Webservice. It offers multiple authorization modules.
It can be plugged in as middleware and offers functions to access the results of the authorization process.

# Usage

```go
    import "github.com/chriss-de/doorman/v2"

    var doormanConfig []*doorman.AuthenticatorConfig
    if err = mapstructure.Decode(viper.Get("permissions"), &doormanConfig); err != nil {
		return err
    }
    
    dm, err = doorman.NewDoorman(
        doorman.WithNewAuthenticatorConfigs(doormanConfig),
        doorman.WithNewAsGlobalDefault(false),
        doorman.WithNewLogger(slog.Default()),
    )

```

## Config options

`WithNewAuthenticatorConfigs(dmc []*doorman.AuthenticatorConfig)` - the configuration for doorman to use

`WithNewRegisterAuthenticator(name string, authenticator RegisterAuthenticatorFunc)` - you can define your own authentication function

`WithNewAsGlobalDefault(force bool)` - doorman offers a global variable OR you can initialize individual doorman's for separate services

`WithNewHashAlgorithm(name string, f HasherFunc)` - some authenticator uses hashes to protect passwords in config files. Currently included are md5, sha1 and sha256. You can add your own has function.

`WithNewLogger(l Logger)` - doorman needs to log messages in some cases. You can add your own logger.

# Configuration

This is an example config with all possible authenticators:
```yaml
- name: ip
  type: ipaddress
  acls:
    - read:app:ip
  addresses:
    - 12.34.56.78/9
```

# Authenticators

There are some basic config parts in every authenticator

```yaml
name: any-name
type: authenticator-module-name
acls:
  - acl1 
```

The name can be any alphanumeric string. 
The type specifies which module to load.
ACLs is a list of strings that can later be checked in your code.

## Basic Authenticator
Handles basic auth requests.

```yaml
- name: basic                                       # any name defined by you
  type: basic                                       # authenticator module
  acls:                                             # if any user defined in this authenticator is successful authenticated
    - read:app                                      # it will get this ACL
  credentials:
    - username: user1                               # username
      password: "7815696ecbf1c96e6894b779456d330e"  # `asdf` md5 hashed
      hashed: "md5"       
      dynamic_acls:
        - acl_added_to_acls                         # if this user authenticated we add this ACL
                                                    # + the ACLs above
```

## HTTP Header Authenticator
You can look for http headers and their values and make authentication decisions

```yaml
- name: apikey                                                                  # any name defined by you
  type: http_header                                                             # authenticator module
  acls:
    - whatever
  headers:
    - name: x-apikey                                                            # http header name to look for
      hashed: "sha256"    
      value: "688787d8ff144c502c7f5cffaafe2cc588d86079f9de88304c26b0cb99ce91c6" # `asdf` sha256 hashed
      capture_headers:                                                          # other headers from the request that should be present in context Info
        - Content-Type
      dynamic_acls:
        - acl_added_to_acls                                                     # request that could be authenticated with this entry get this ACL too
```

## IP address Authenticator
You can authenticate by ip addresses and networks

```yaml
- name: ip                # any name defined by you
  type: ipaddress         # authenticator module
  acls:
    - authed_by_network
  addresses:
    - 12.34.56.78/8       # address in CIDR notation
```

## Bearer Authenticator
You can use any openID connect IDP with JWT tokens for authentication

```yaml
- name: bearer
  type: bearer
  # one of
  jwks_url: [issuer]/protocol/openid-connect/certs
  meta_url: [issuer]/.well-known/openid-configuration
#  keys_fetch_interval: 1h

#  token_key_aliases: {}
#  token_map_acls: []
#  claims_validations: []
```

### Token Key Aliases
Is a map of original key to an alias to be used in your application.
```yaml
- token_key_aliases:
    - orig.key.in.token:  new_name
```

Now you can look for values in token with the key `new_name`

### Token Map ACLs
With `token_map_acls` you can map an entier part (mostly a list) as ACLs

### Claims Validations
You validate every key in the token with a claim_validation

```yaml
- key: key.in.token    # nested token keys can be separated with `.`
  optional: bool       # if true we don't stop and still consider this token for further processing
  dynamic_acls: []     # if this validation is successful we add those ACLs to the InfoContext
  validations:         # JWT are JSON objects
    - operations: type # length | type | equal | contains
                       # length works on strings, integer, slices, map
                       # type tries to check if string, number, list, map, bool
                       # equal checks if it equal
                       # contains check if the value is in the list
      value: wanted    # used in every operation as the value we expect/want
      optional: bool   # if true this validation must not succeed
```


## Info Context
When you use doorman as middleware every successful authentication will generate a list of InfoContext 
with a list of ACLs

```go
type Info struct {
	Infos []AuthenticatorInfo
	ACLs  map[string]struct{}
}
```

You can access this context like

```go
dmInfo, err := doorman.InfoFromContext(ctx)
```

## Helper functions

To make life easier you can use helper functions that check if ACLs are present or to lookup a key in a bearer token.

```go
if r, err := doorman.HasACL(r.Context(), "ANY_STRING"); err != nil && r {
	// allow access
}

if s, err := doorman.GetStringFromToken("key.in.token.or.alias"); err != nil {
	// use s 
}
```