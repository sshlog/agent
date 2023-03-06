#!/bin/bash

if [ -z "$PACKAGE_SIGNING_KEY" ]
then
	# GPG key is NOT set in environment variables
      echo "Skipping GPG signing for packages because env var is missing: PACKAGE_SIGNING_KEY"
else
	echo "$PACKAGE_SIGNING_KEY" > /tmp/signing.key
	# Replace "\n" with newlines in case it is an env var as a single line
	sed -Ei 's/\\n/\n/g' /tmp/signing.key
	gpg --allow-secret-key-import --import /tmp/signing.key
	echo "cert-digest-algo SHA256" >> ~/.gnupg/gpg.conf
	echo "digest-algo SHA256" >> ~/.gnupg/gpg.conf
fi


