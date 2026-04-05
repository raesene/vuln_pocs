# Vulnerability PoCs

This is a repository that contains some proof of concepts that are handy for demos :)

- CVE-2020-8554 - This is one of the four unpatchable Kubernetes vulnerabilities and the exploit shows how a user with the right permissions can hijack traffic from other users in the cluster.

- CVE-2020-8562 - Another one of the unpatchable four, this is a TOCTOU vulnerability that allows a user with rights to use the API server proxy to get access to the localhost interface on the API server (it can also be used for other targets that would be blocked like 169.254.169.254)

- CVE-2021-25740 - Another one  of the unpatchable four, this demonstrates how a user with access to a shared ingress resource can get access to pods that they would otherwise not be able to reach due to network policies.

- CVE-2021-30465 - Another TOCTOU vulnerability, this one allows access to files from the host's filesystem.

- CVE-2022-23648 - This is a containerd CVE that allows for access to files from the underlying host.

- CVE-2025-31133 - A TOCTOU race condition in runc's maskedPaths handling that allows container escape by replacing /dev/null with a symlink during container setup.
