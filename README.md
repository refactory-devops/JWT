# RFY.JsonApi.Authenticator
[![Code Climate](https://codeclimate.com/github/rfyio/RFY.JsonApi.Authenticator/badges/gpa.svg)](https://codeclimate.com/github/rfyio/RFY.JsonApi.Authenticator)
[![Test Coverage](https://codeclimate.com/github/rfyio/RFY.JsonApi.Authenticator/badges/coverage.svg)](https://codeclimate.com/github/rfyio/RFY.JsonApi.Authenticator/coverage)
[![Build Status](https://travis-ci.org/rfyio/RFY.JsonApi.Authenticator.svg)](https://travis-ci.org/rfyio/RFY.JsonApi.Authenticator)

## Working in progress.....


This package is meant to make a POST authentication possible for any Json based authentication attempt.

The possible responses are:

- AuthenticationSuccessfull which returns the authenticated user-ID
- AuthenticationFailure which returns a message with the corresponding error code

## Getting started

To start using this package you will need to do the following steps:

To incluse this package into your TYPO3 Flow application just run:

	composer require rfy/jsonapi/authenticator

Add the below YAML to the projects `Configuration/Routes.yaml`:

```
	-
	  name: 'Session'
	  uriPattern: '<SessionSubroutes>'
	  defaults:
	    '@format': 'json'
	  subRoutes:
	    SessionSubroutes:
	      package: RFY.JsonApi.Authenticator
```

### Intended Features:


Authors:
--------

Author: Sebastiaan van Parijs (<svparijs@refactory.it>)

License:
--------
Copyright 2015 Sebastiaan van Parijs

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