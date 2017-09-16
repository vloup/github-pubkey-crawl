#!/bin/sh

dub build

retcode=-1
while [ "$retcode" -ne 0 ]; do
	./github-pubkey-crawl -w 20
	retcode=$?
	if [ "$retcode" -ne 0 ]; then
		echo "API Limit reached, waiting for an hour."
		sleep 1h
	fi
done
