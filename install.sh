#!/bin/bash

set -eo pipefail

cd $(dirname "$0")

script="check-librus.sh"


if test -e "$script"; then
    echo "File $script already exists"
else
    cat <<EOF > "$script"
#!/bin/bash

set -xeuo pipefail

export LIBRUS_USER=
export LIBRUS_PASS=
# export LIBRUS_NAME=

export SMTP_USER=
export SMTP_PASS=
export SMTP_SERVER=

export EMAIL_DEST=

#export DB_NAME=pylibrus.sqlite

#export FETCH_ATTACHMENTS=yes

# define which messages to sent
# - unread - send messages unread in librus
# - unsent - send messages not marked in DB as sent
#export SEND_MESSAGE=unread

#export MAX_AGE_OF_SENDING_MSG_DAYS=4

cd "${PWD}"

uv run src/pylibrus/pylibrus.py

EOF

    chmod +x "$script"
fi;

[[ -e pylibrus.ini  ]] || cp pylibrus.ini.example pylibrus.ini

script_abs_path=$(readlink -f "$script")

cat <<EOF

Make sure all parameters in pylibrus.ini are valid, alternatively
to finish installation set all variables in "$script_abs_path".

To send testing email run:
TEST_EMAIL_CONF=1 "$script_abs_path"

To run it periodically add entry to your crontab (to edit your crontab run "crontab -e"):

*/10 * * * * "$script_abs_path"

EOF
