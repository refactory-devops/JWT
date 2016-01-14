# RFY.JWT
[![Code Climate](https://codeclimate.com/github/rfyio/JWT/badges/gpa.svg)](https://codeclimate.com/github/rfyio/JWT)
[![Test Coverage](https://codeclimate.com/github/rfyio/JWT/badges/coverage.svg)](https://codeclimate.com/github/rfyio/JWT/coverage)
[![Build Status](https://travis-ci.org/rfyio/JWT.svg?branch=master)](https://travis-ci.org/rfyio/JWT)

This package is meant to make a TOKEN authentication possible for any request authentication attempt.

The possible responses are:

- AuthenticationSuccessfull which returns the authentication JWT token
- AuthenticationFailure which returns a message with the corresponding error code


## Getting started

To start using this package you will need to follow the following steps:

Include this package into your TYPO3 Flow application by running:

	composer require rfy/jwt

Add the below YAML to the projects `Configuration/Routes.yaml`:

```yaml
-
  name: 'Token'
  uriPattern: '<TokenSubroutes>'
  defaults:
    '@format': 'json'
  subRoutes:
    TokenSubroutes:
      package: RFY.JWT
```

By default the security features are enabled in this package by these settings:

```yaml
TYPO3:
  Flow:
    security:
      authentication:
        providers:
          'BackendProvider':
            provider: 'RFY\JWT\Security\Authentication\Provider\PersistedApiTokenProvider'
            token: 'RFY\JWT\Security\Authentication\Token\ApiToken'
            entryPoint: 'HttpBasic'
```
You of course overwrite these settings based on your wishes.

### References:

This implementation requires the [Firebase JWT package](https://github.com/firebase/php-jwt).

#### Authors:
Author: Sebastiaan van Parijs (<svparijs@rfy.io>)

#### Feedback & Reviews:

Reviewer: Bastian Waidelich

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.