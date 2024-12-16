## pyLibrus

Message scraper from crappy Librus Synergia gradebook. Forwards every new
message from a given folder to an e-mail.

## Linux installation (semi manual)

* Make sure you have installed `git`, `uv` and `python3`
* Checkout **pylibrus** repository and run `install.sh` script
* Setup parameters in `check_librus.sh` (path provided in `install.sh` output)
* Setup cron entry to run script periodically (details in `install.sh` output)

## Manual usage

Parameters are passed through environment:
* `DB_NAME` - file with SQLite database of sent messages
* `LIBRUS_USER` - login to Librus
* `LIBRUS_PASS` - password to Librus
* `SMTP_USER` - login to `SMTP_SERVER` (also the originator of the e-mail sent)
* `SMTP_PASS` - password to `SMTP_SERVER`
* `SMTP_SERVER` - SMTP server address (e.g. `smtp.gmail.com`)
* `EMAIL_DEST` - destination to send e-mail, may be many e-mails separated by `,`

Example shell script to run in loop, to be launched from `tmux` or `screen`:

```bash
#!/bin/bash

source venv/bin/activate

set -xeuo pipefail

export LIBRUS_USER=...
export LIBRUS_PASS=...

export SMTP_USER=...
export SMTP_PASS=...
export SMTP_SERVER=...

export EMAIL_DEST=...

while true; do
        python pylibrus.py
        sleep 600
done
```

**WARNING**: only GMail SMTP server was tested.

## Potential improvements

* support HTML messages
* support announcements
* support calendar
