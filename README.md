# caddy-kubernetes-storage

Kubernetes storage for caddy's TLS data

Running within a kubernetes pod
-------------------------------
All that is needed is adding the `storage "kubernetes"` directive to the tls block in your caddy file

Running outside a kubernetes pod, or with a custom config
---------------------------------------------------------
Add the `storage "kubernetes"` directive to the tls block in your caddy file, in addition, define the following environment variables:

- `CADDY_K8S_CONF_PATH`: The path to a JSON kubernetes config file. The JSON format corresponds to the kubernetes config struct found [here]( https://github.com/kubernetes/kubernetes/blob/release-1.3/pkg/client/restclient/config.go#L42)
- `CADDY_K8S_NAMESPACE`: The namespace to use for creating and retrieving secrets.

License
-------
This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at http://mozilla.org/MPL/2.0/.