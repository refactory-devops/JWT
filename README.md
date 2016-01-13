# RFY.JsonApi.Authenticator
[![Latest Version on Packagist][ico-version]][link-packagist]
[![Code Climate](https://codeclimate.com/github/rfyio/JWT/badges/gpa.svg)](https://codeclimate.com/github/rfyio/JWT)
[![Test Coverage](https://codeclimate.com/github/rfyio/JWT/badges/coverage.svg)](https://codeclimate.com/github/rfyio/JWT/coverage)
[![Build Status](https://travis-ci.org/rfyio/RFY.JsonApi.Authenticator.svg)](https://travis-ci.org/rfyio/RFY.JsonApi.Authenticator)
[![Software License][ico-license]](LICENSE.md)
[![Total Downloads][ico-downloads]][link-downloads]

This package is meant to make a TOKEN authentication possible for any request authentication attempt.

The possible responses are:

- AuthenticationSuccessfull which returns the authentication JWT token
- AuthenticationFailure which returns a message with the corresponding error code


## Getting started

To start using this package you will need to follow the following steps:

Include this package into your TYPO3 Flow application by running:

	composer require rfy/jsonapi-authenticator

Add the below YAML to the projects `Configuration/Routes.yaml`:

```yaml
-
  name: 'Token'
  uriPattern: '<TokenSubroutes>'
  defaults:
    '@format': 'json'
  subRoutes:
    TokenSubroutes:
      package: RFY.JsonApi.Authenticator
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

## Example use case
Currently I use this in combination with the `UsernamePasswordHttpBasic` token, so you authenticate the first time with your username and password.
This will result in a JSON response containing the JWT Authentication Token which you set as a cookie, Authorization header or argument for each following request.

```yaml
TYPO3:
  Flow:
    security:
      authentication:
        providers:
          'HttpBasicProvider':
            provider: 'PersistedUsernamePasswordProvider'
            token: 'TYPO3\Flow\Security\Authentication\Token\UsernamePasswordHttpBasic'
            entryPoint: 'HttpBasic'
```

### Intended Features:

- Optional security params checked, like creationDate, expirationDate & IP-Address.

### References:

This implementation requires the [Firebase JWT package](https://github.com/firebase/php-jwt).

#### Authors:
Author: Sebastiaan van Parijs (<svparijs@rfy.io>)

#### Feedback & Reviews:

Reviewer: Bastian Waidelich

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.