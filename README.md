# caddy-kubernetes-storage

Kubernetes storage for caddy's TLS data

Running within a kubernetes pod
-------------------------------
All that is needed is adding the `storage "kubernetes"` directive to the tls block in your caddy file

Running outside a kubernetes pod, or with a custom config
---------------------------------------------------------
Add the `storage "kubernetes"` directive to the tls block in your caddy file, in addition, define the following environment variables:

- `CADDY_K8S_CONF_PATH`: The path to a JSON kubernetes config file. The JSON format corresponding to the kubernetes config struct found [here]( https://github.com/kubernetes/kubernetes/blob/release-1.3/pkg/client/restclient/config.go#L42)
- `CADDY_K8S_NAMESPACE`: The namespace to use for creating and retrieving secrets.

Storage method
--------------
The plugin will create kubernetes secrets to store TLS certificates, user data as well as email data.
The naming scheme for the secrets looks as follows:

- Domain specific data: `caddy-domain-[domain name]`
- User specific data: `caddy-user-[base64 url-encoded email]`
- Global data: `caddy-global`

Installation
------------
You should vendor the `k8s.io/kubernetes` repository in your own code, and use the correct `release-1.x` branch that corresponds with the version of kubernetes that you use.
This is because the master branch of `k8s.io/kubernetes` is meant for the in development version of kubernetes, which your cluster is probably not running, and often does not compile.

This code is tested with the latest release branch of kubernetes, currently that is `release-1.3`

Once you have the correct version of kubernetes vendored, you can just run `go get github.com/PalmStoneGames/caddy-kubernetes-storage/...`

License
-------
This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at http://mozilla.org/MPL/2.0/.