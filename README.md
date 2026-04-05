# Vulnerability PoCs

This is a repository that contains some proof of concepts that are handy for demos :) I'm also experimenting with whether LLMs are good at creating PoCs and generated documentation about them.

- kinvolk-proxy-exploit - This doesn't have a CVE (although perhaps it should), demonstrates a technique discovered by Kinvolk, where a user with rights to proxy to a pod in a Kubernetes cluster, can execute an SSRF attack in the cluster.

- CVE-2020-8554 - This is one of the four unpatchable Kubernetes vulnerabilities and the exploit shows how a user with the right permissions can hijack traffic from other users in the cluster.

- CVE-2020-8561 - Another one of the unpatchable four, this essentially combines (ab)use of existing Kubernetes features to get an SSRF from the Kubernetes API server.

- CVE-2020-8562 - Another one of the unpatchable four, this is a TOCTOU vulnerability that allows a user with rights to use the API server proxy to get access to the localhost interface on the API server (it can also be used for other targets that would be blocked like 169.254.169.254)

- CVE-2021-25740 - Another one  of the unpatchable four, this demonstrates how a user with access to a shared ingress resource can get access to pods that they would otherwise not be able to reach due to network policies.

- CVE-2021-30465 - Another TOCTOU vulnerability, this one allows access to files from the host's filesystem.

- CVE-2022-23648 - This is a containerd CVE that allows for access to files from the underlying host.

- CVE-2025-31133 - An LLM Generated PoC of a TOCTOU race condition in runc's maskedPaths handling that allows container escape by replacing /dev/null with a symlink during container setup.
