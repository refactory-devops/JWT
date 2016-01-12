# RFY.JsonApi.Authenticator
[![Code Climate](https://codeclimate.com/github/rfyio/RFY.JsonApi.Authenticator/badges/gpa.svg)](https://codeclimate.com/github/rfyio/RFY.JsonApi.Authenticator)
[![Test Coverage](https://codeclimate.com/github/rfyio/RFY.JsonApi.Authenticator/badges/coverage.svg)](https://codeclimate.com/github/rfyio/RFY.JsonApi.Authenticator/coverage)
[![Build Status](https://travis-ci.org/rfyio/RFY.JsonApi.Authenticator.svg)](https://travis-ci.org/rfyio/RFY.JsonApi.Authenticator)

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
            provider: 'RFY\JsonApi\Authenticator\Security\Authentication\Provider\PersistedApiTokenProvider'
            token: 'RFY\JsonApi\Authenticator\Security\Authentication\Token\ApiToken'
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
Author: Sebastiaan van Parijs (<svparijs@refactory.it>)

#### Feedback & Reviews:

Reviewer: Bastian Waidelich

License:
--------
Copyright 2015 Refactory

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.