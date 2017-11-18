github-pubkey-crawl
===================

This tool serves to gather all public keys on GitHub as well as their
corresponding user name and user id.

Getting started
---------------

* Make sure you have a dlang toolchain installed (`dmd`, `ldc` or `gdc`).
* Do not forget to install the `dub` build tool.
* You can directly use the `crawl.sh` script or you may compile the code with
  `dub build --arch=x86_64` and use the newly created binary. In the second
  case, using the `-h` or `--help` switch will show the tool possibilities.

Options
-------

* `-o`, `--output`: specify the output file (default is `github-pubkey.csv`).
* `-i`, `--id`: give the starting id.
* `--ask-password`: avoid caching the password into the `login-info` file.
* `-w`, `--worker`: give a different amount of public keys download workers
  (default is 10)

Two-factor authentication
-------------------------

If you are using 2FA, you will need to create a personal access token [here](https://github.com/settings/tokens) and use the generated password instead of your regular password.
Make sure to have enough access to read users and their public keys.

Licence
-------

This tool is licenced under the GPLv3.
