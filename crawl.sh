#!/bin/sh

dub build

retcode=254
while [ "$retcode" -eq 254 ]; do
	./github-pubkey-crawl -w 20
	retcode=$?
	if [ "$retcode" -eq 254 ]; then
		echo "API Limit reached, waiting for an hour."
		sleep 1h
	fi
done
