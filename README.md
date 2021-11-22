# Authentication Service

This is a rewrite of the [arrikto/oidc-authservice](https://github.com/arrikto/oidc-authservice) project to be as simple as possible.

An Authentication Service is an HTTP Server that an API Gateway (eg Ambassador, Envoy) asks if an incoming request is authorized.

* * *
## OpenID Connect

[OpenID Connect (OIDC)](http://openid.net/connect/) is an authentication layer on top of the OAuth 2.0 protocol. As OAuth 2.0 is fully supported by OpenID Connect, existing OAuth 2.0 implementations work with it out of the box.

Currently it only supports OIDC's [Authorization Code Flow](http://openid.net/specs/openid-connect-basic-1_0.html#CodeFlow), similar to OAuth 2.0 Authorization Code Grant.

* * *
## About 👯‍♂️

With ❤️ from [YData](https://ydata.ai) | [Development Team](mailto://developers@ydata.ai)
