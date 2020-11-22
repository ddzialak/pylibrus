## pyLibrus

Message scraper from crappy Librus Synergia gradebook. Forwards every new
message from a given folder to an e-mail.

## Linux installation (semi manual)

* Make sure you have installed `git`, `uv` and `python3`
* Checkout **pylibrus** repository and run `install.sh` script
* Configure account using at least one of:
  * Configure via environment variables directly in `check_librus.sh`
  * Configure `pylibrus.ini` (recommended for more than one child)
* Setup cron entry to run script periodically (details in `install.sh` output)

## Manual usage

Parameters are passed through environment:
* `LIBRUS_USER` - login to Librus
* `LIBRUS_PASS` - password to Librus
* `LIBRUS_NAME` - name used as prefix in email subject or webhook
* `SMTP_USER` - login to `SMTP_SERVER` (also the originator of the e-mail sent)
* `SMTP_PASS` - password to `SMTP_SERVER`
* `SMTP_SERVER` - SMTP server address (e.g. `smtp.gmail.com`)
* `EMAIL_DEST` - destination to send e-mail, may be many e-mails separated by `,`

* `DB_NAME` - file with SQLite database of sent messages (by default "pylibrus.sqlite", ignored if DB_URL is set)
* `DB_URL` - url to DB (by default SQLite database: sqlite:///${DB_NAME}).

   To use with mysql additional actions are required:
   * additional packages required: `sudo apt-get install clang libmysqlclient-dev python-dev-is-python3`
   * then install python packages in virtual env (`uv pip install mysql mysql-connector-python`)

   then setup `DB_URL=mysql+mysqlconnector://user:PASSWD@HOST:3306/database`


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


## Potential improvements

* support HTML messages
* support announcements
* support calendar
