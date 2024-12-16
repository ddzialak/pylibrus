import abc
import base64
import configparser
import dataclasses
import datetime
import json
import logging
import os
import smtplib
import sys
import time
from configparser import ConfigParser
from email.message import EmailMessage
from http import client as http_client
from itertools import chain
from textwrap import dedent

import requests
from bs4 import BeautifulSoup
from sqlalchemy import Column, String, Boolean, DateTime, Integer, LargeBinary, ForeignKey
from sqlalchemy.engine import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from user_agent import generate_user_agent

Base = declarative_base()

FAILED_TO_DOWNLOAD_ATTACHMENT_DATA = "Failed to download attachment data!"
CONFIG_FILE_PATH = os.path.realpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "pylibrus.ini"))
STORED_COOKIES_PATH = os.path.realpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "pylibrus_cookies.json"))
TRUE_VALUES = ('yes', 'on', 'true', '1')
FALSE_VALUES = ('no', 'off', 'false', '0')


class MissingParameterException(ValueError):
    pass


def str_to_bool(s: str):
    if s is None:
        return None
    s = s.lower()
    if s in TRUE_VALUES:
        return True
    elif s in FALSE_VALUES:
        return False
    else:
        raise ValueError(f"Invalid boolean value: {s}. Should be one of: {list(TRUE_VALUES) + list(FALSE_VALUES)} ")


def str_to_int(s: str):
    if s is None:
        return None
    return int(s)

@dataclasses.dataclass(slots=True)
class PyLibrusConfig:
    send_message: str = "unread"
    fetch_attachments: bool = True
    max_age_of_sending_msg_days: int = 4
    db_name: str = "pylibrus.sqlite"
    db_url: str = ""
    debug: bool = False
    sleep_between_librus_users: int = 10

    inbox_folder_id: int = dataclasses.field(default=5, init=False)  # Odebrane

    def __post_init__(self):

        def convert_str_to_type(value: str, _type: type):
            # it could be: globals()[f"str_to_{_type.__name__}"](value)
            # but want to keep function references
            match _type.__name__:
                case "bool":
                    return str_to_bool(value)
                case "int":
                    return str_to_int(value)
            raise AssertionError(f"Non supported type in config: {_type} ({value=}")

        for field in dataclasses.fields(self):
            if not isinstance(field.default, dataclasses._MISSING_TYPE) and getattr(self, field.name) is None:
                setattr(self, field.name, field.default)
            else:
                value = getattr(self, field.name)
                if not isinstance(value, field.type):
                    setattr(self, field.name, convert_str_to_type(value, field.type))
        if self.send_message not in ("unread", "unsent"):
            raise ValueError("SEND_MESSAGE should be 'unread' or 'unsent'")

        if not self.db_url:
            self.db_url = "sqlite:///" + self.db_name

    @staticmethod
    def get_config_str(config, envs: dict, name: str, section='global'):
        value = ""
        if config:
            cfg_name = getattr(PyLibrusConfig, name.lower()).__name__
            value = config[section].get(cfg_name, None)
        if not value:
            value = envs.get(name.upper(), "")
        return value

    @classmethod
    def read_config(cls, cfg: ConfigParser, env: dict) -> "PyLibrusConfig":
        kwargs = {}
        for param in ('db_name', 'db_url', 'send_message', 'fetch_attachments', 'debug', 'sleep_between_librus_users', 'max_age_of_sending_msg_days'):
            value = PyLibrusConfig.get_config_str(cfg, env, param)
            if value:
                kwargs[param] = value
        return cls(**kwargs)

    @classmethod
    def read_users(cls, cfg: ConfigParser, env: dict) -> list["PyLibrusUser"]:
        librus_users = LibrusUser.load_librus_users_from_config(cfg, env)
        try:
            user_from_env = LibrusUser.from_env(env)
        except MissingParameterException as ex:
            if not librus_users:
                print(f"Missing valid user in env: {ex}")
                raise MissingParameterException("Configuration file neither environment has valid user definition")
        else:
            librus_users.append(user_from_env)
        return librus_users


PYLIBRUS_CONFIG: PyLibrusConfig | None = None

def validate_fields(instance):
    for field in dataclasses.fields(instance):
        value = getattr(instance, field.name)
        if value is None or value == "":
            raise MissingParameterException(f"The field '{field.name}' cannot be None.")


class Notify(abc.ABC):
    @staticmethod
    def is_email() -> bool:
        return False

    @staticmethod
    def is_webhook() -> bool:
        return False


@dataclasses.dataclass(slots=True)
class EmailNotify(Notify):
    smtp_user: str
    smtp_pass: str = dataclasses.field(repr=False)
    smtp_server: str
    email_dest: list[str] | str
    smtp_port: int = 587

    @staticmethod
    def is_email() -> bool:
        return True

    def __post_init__(self):
        if isinstance(self.email_dest, str):
            self.email_dest = [email.strip() for email in self.email_dest.split(",")]
        for field in dataclasses.fields(self):
            if not isinstance(field.default, dataclasses._MISSING_TYPE) and getattr(self, field.name) is None:
                setattr(self, field.name, field.default)
        validate_fields(self)

    @classmethod
    def from_env(cls, env: dict[str, str]) -> "EmailNotify":
        port = env.get("SMTP_PORT")
        kwargs = {"smtp_port": int(port)} if port else {}
        return cls(
            smtp_user=env.get("SMTP_USER", "Default user"),
            smtp_pass=env.get("SMTP_PASS"),
            smtp_server=env.get("SMTP_SERVER"),
            email_dest=env.get("EMAIL_DEST"),
            **kwargs
        )

    @classmethod
    def from_config(cls, config, section, env) -> "EmailNotify":
        section = config[section]

        def get_param(name):
            return section.get(name) or config["global"].get(name) or env.get(name.upper())

        port = get_param('smtp_port')
        kwargs = {'smtp_port': int(port)} if port else {}
        return cls(
            smtp_user=get_param('smtp_user'),
            smtp_pass=get_param('smtp_pass'),
            smtp_server=get_param('smtp_server'),
            email_dest=get_param('email_dest'),
            **kwargs,
        )


@dataclasses.dataclass(slots=True)
class WebhookNotify(Notify):
    webhook: str

    @staticmethod
    def is_webhook() -> bool:
        return True

    def __post_init__(self):
        validate_fields(self)

    @classmethod
    def from_env(cls, envs: dict) -> "WebhookNotify":
        return cls(webhook=envs.get("WEBHOOK"))

    @classmethod
    def from_config(cls, config, section):
        return cls(webhook=config[section]['webhook'])


@dataclasses.dataclass(slots=True)
class LibrusUser:
    login: str
    password: str = dataclasses.field(repr=False)
    name: str
    notify: EmailNotify | WebhookNotify

    @classmethod
    def from_config(cls, config, section, env: dict[str, str]) -> "LibrusUser":
        name = section.split(':', 1)[1]
        librus_user = config[section].get('librus_user')
        librus_pass = config[section].get('librus_pass')
        # Determine whether the user uses email or webhook notification
        if config[section].get('email_dest'):
            notify = EmailNotify.from_config(config, section, env)
        elif config[section].get('webhook'):
            notify = WebhookNotify.from_config(config, section)
        else:
            raise MissingParameterException(f"No valid notification method for {section}")
        return cls(name=name, login=librus_user, password=librus_pass, notify=notify)

    @classmethod
    def from_env(cls, env) -> "LibrusUser":
        return cls(
            login=env.get("LIBRUS_USER"),
            password=env.get("LIBRUS_PASS"),
            name=env.get("LIBRUS_NAME"),
            notify=WebhookNotify.from_env(env) if env.get("WEBHOOK") else EmailNotify.from_env(env)
        )

    @classmethod
    def load_librus_users_from_config(cls, config: ConfigParser, env: dict) -> list["LibrusUser"]:
        users = []
        for section in config.sections():
            if section.startswith("user:"):
                try:
                    user = cls.from_config(config, section, env=env)
                except MissingParameterException as ex:
                    print(f"Section {section} has no valid user definition: {ex}")
                else:
                    users.append(user)
        return users


class Msg(Base):
    __tablename__ = "messages"

    url = Column(String(1024), primary_key=True)
    folder = Column(Integer)
    sender = Column(String(1024))
    subject = Column(String(4096))
    date = Column(DateTime)
    contents_html = Column(String(409600))
    contents_text = Column(String(409600))
    email_sent = Column(Boolean, default=False)


class Attachment(Base):
    __tablename__ = "attachments"

    link_id = Column(String(256), primary_key=True)  # link_id seems to contain message id and attachment id
    msg_path = Column(String(1024), ForeignKey(Msg.url))
    name = Column(String(1024))
    data = Column(LargeBinary)


def retrieve_from(txt, start, end):
    pos = txt.find(start)
    if pos == -1:
        return ""
    idx_start = pos + len(start)
    pos = txt.find(end, idx_start)
    if pos == -1:
        return ""
    return txt[idx_start:pos].strip()

class LibrusScraper(object):
    API_URL = "https://api.librus.pl"
    SYNERGIA_URL = "https://synergia.librus.pl"

    @classmethod
    def get_attachment_download_link(cls, link_id: str):
        return f"{cls.SYNERGIA_URL}/wiadomosci/pobierz_zalacznik/{link_id}"

    @classmethod
    def synergia_url_from_path(cls, path):
        if path.startswith("https://"):
            return path
        return cls.SYNERGIA_URL + path

    @classmethod
    def api_url_from_path(cls, path):
        return cls.API_URL + path

    @staticmethod
    def msg_folder_path(folder_id):
        return f"/wiadomosci/{folder_id}"

    def __init__(self, login, passwd, debug=False, cookies=None):
        self._login = login
        self._passwd = passwd
        self._session = requests.session()
        self._user_agent = generate_user_agent()
        self._last_folder_msg_path = None
        self._last_url = self.synergia_url_from_path("/")
        self.set_cookies(cookies)

        if debug:
            http_client.HTTPConnection.debuglevel = 1
            logging.basicConfig()
            logging.getLogger().setLevel(logging.DEBUG)
            requests_log = logging.getLogger("requests.packages.urllib3")
            requests_log.setLevel(logging.DEBUG)
            requests_log.propagate = True

    def _set_headers(self, referer, kwargs):
        if "headers" not in kwargs:
            kwargs["headers"] = {}
        kwargs["headers"].update(
            {
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "pl",
                "User-Agent": self._user_agent,
                "Referer": referer,
            }
        )
        return kwargs

    def _api_post(self, path, referer, **kwargs):
        debug(f"post {path}")
        self._set_headers(referer, kwargs)
        return self._session.post(self.api_url_from_path(path), **kwargs)

    def _api_get(self, path, referer, **kwargs):
        debug(f"get {path}")
        self._set_headers(referer, kwargs)
        return self._session.get(self.api_url_from_path(path), **kwargs)

    def _request(self, method, path, referer=None, **kwargs):
        if referer is None:
            referer = self._last_url
        debug(f"{method} {path} referrer={referer}")
        self._set_headers(referer, kwargs)
        url = self.synergia_url_from_path(path)
        debug(f"Making reuqest: {method} {url} with cookies: {self._session.cookies.get_dict()}")
        if method == "get":
            resp = self._session.get(url, **kwargs)
        elif method == "post":
            resp = self._session.post(url, **kwargs)
        else:
            raise AssertionError(f"Unsupported method: {method}")
        self._last_url = resp.url
        return resp

    def _post(self, path, referer=None, **kwargs):
        return self._request("post", path, referer, **kwargs)

    def _get(self, path, referer=None, **kwargs):
        return self._request("get", path, referer, **kwargs)

    def clear_cookies(self):
        self._session.cookies.clear()

    def set_cookies(self, cookies_dict):
        self._cookies = cookies_dict if cookies_dict else {}
        self._session.cookies.update(requests.utils.cookiejar_from_dict(self._cookies))

    def are_cookies_valid(self):
        self._session.get(self.synergia_url_from_path("/rodzic/index"))
        msgs = self.msgs_from_folder(PYLIBRUS_CONFIG.inbox_folder_id)
        return len(msgs) > 0

    def __enter__(self):

        if self.are_cookies_valid():
            print(f"{self._login} COOKIES ARE VALID!")
            return self
        print(f"{self._login} COOKIES ARE NOT VALID - LOGIN!")
        self.clear_cookies()
        oauth_auth_frag = "/OAuth/Authorization?client_id=46"
        oauth_auth_url = self.api_url_from_path(oauth_auth_frag)
        oauth_2fa_frag = "/OAuth/Authorization/2FA?client_id=46"

        self._api_get(
            f"{oauth_auth_frag}&response_type=code&scope=mydata",
            referer="https://portal.librus.pl/rodzina/synergia/loguj",
        )
        resp = self._api_post(
            oauth_auth_frag,
            referer=oauth_auth_url,
            data={
                "action": "login",
                "login": self._login,
                "pass": self._passwd,
            },
        )
        if resp.status_code // 100 != 2:
            raise AssertionError(f"Login response {resp}")
        self._api_get(oauth_2fa_frag, referer=oauth_auth_url)
        self._cookies = self._session.cookies.get_dict()
        return self

    def __exit__(self, exc_type=None, exc_val=None, exc_tb=None):
        pass
    "#body > div.container.static > div > table > tbody > tr:nth-child(1) > td"

    @staticmethod
    def _find_msg_header(soup, name):
        header = soup.find_all(string=name)
        return header[0].parent.parent.parent.find_all("td")[1].text.strip()

    def fetch_attachments(self, msg_path, soup, fetch_content):

        header = soup.find_all(string="Pliki:")
        if not header:
            return []

        def get_attachments_without_data() -> list[Attachment]:
            attachments = []
            for attachment in header[0].parent.parent.parent.next_siblings:
                _black_dies_without_that_name = r""" Example of str(attachment):
                <tr>
                <td>
                <!-- icon -->
                <img src="/assets/img/filetype_icons/doc.png"/>
                <!-- name -->
                                        KOPIOWANIE.docx                    </td>
                <td>
                                         
                                        <!-- download button -->
                <a href="javascript:void(0);">
                <img class="" onclick='

                                        otworz_w_nowym_oknie(
                                            "\/wiadomosci\/pobierz_zalacznik\/4921079\/3664030",
                                            "o2",
                                            420,
                                            250                        )

                                                    ' src="/assets/img/homework_files_icons/download.png" title=""/>
                </a>
                </td>
                </tr>
                """
                name = retrieve_from(str(attachment), "<!-- name -->", "</td>")
                if not name:
                    continue
                link_id = retrieve_from(str(attachment).replace("\\", ""), "/wiadomosci/pobierz_zalacznik/", '",')
                attachments.append(Attachment(link_id=link_id, msg_path=msg_path, name=name, data=None))

            return attachments

        attachments = get_attachments_without_data()

        if not fetch_content:
            return attachments

        for attachment in attachments:
            print(f"Download attachment {attachment.name}")
            download_link = LibrusScraper.get_attachment_download_link(str(attachment.link_id))
            attachment_page = self._get(download_link)

            attach_data = None
            reason = ""
            download_key = retrieve_from(attachment_page.text, 'singleUseKey = "', '"')
            if download_key:
                referer = attachment_page.url
                check_key_url = "https://sandbox.librus.pl/index.php?action=CSCheckKey"
                get_attach_url = f"https://sandbox.librus.pl/index.php?action=CSDownload&singleUseKey={download_key}"
                for _ in range(15):
                    check_ready = self._post(
                        check_key_url,
                        headers={"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"},
                        referer=referer,
                        data=f"singleUseKey={download_key}",
                    )

                    if check_ready.json().get("status") == "ready":
                        get_attach_resp = self._get(get_attach_url)
                        break
                    else:
                        print(f"Waiting for doc: {check_ready.json()}")
                    time.sleep(1)
                else:
                    reason = "waiting for CSCheckKey singleUseKey ready"
            elif "onload=\"window.location.href = window.location.href + '/get';" in attachment_page.text:
                get_attach_resp = self._get(attachment_page.url + "/get")
            else:
                reason = FAILED_TO_DOWNLOAD_ATTACHMENT_DATA

            if get_attach_resp is not None:
                if get_attach_resp.ok:
                    attach_data = get_attach_resp.content
                else:
                    reason = f"http status code: {get_attach_resp.status_code}"

            if reason:
                reason = f"Failed to download attachment: {reason}"
                print(reason)
                attach_data = reason.encode()

            attachment.data=attach_data
            print(f"Attachment name={attachment.name}, link={attachment.link_id}, size: {len(attach_data)}")

        return attachments

    def fetch_msg(self, msg_path, fetch_attchement_content: bool):
        global PYLIBRUS_CONFIG
        msg_page = self._get(msg_path, referer=self.synergia_url_from_path(self._last_folder_msg_path)).text
        soup = BeautifulSoup(msg_page, "html.parser")
        sender = self._find_msg_header(soup, "Nadawca")
        subject = self._find_msg_header(soup, "Temat")
        date_string = self._find_msg_header(soup, "Wysłano")
        date = datetime.datetime.strptime(date_string, "%Y-%m-%d %H:%M:%S")
        if datetime.datetime.now() - date > datetime.timedelta(days=PYLIBRUS_CONFIG.max_age_of_sending_msg_days):
            print(f"Do not send '{subject}' (message too old, {date})")
            return None
        contents = soup.find_all(attrs={"class": "container-message-content"})[0]

        attachments = self.fetch_attachments(msg_path, soup, fetch_attchement_content)
        return sender, subject, date, str(contents), contents.text, attachments

    def msgs_from_folder(self, folder_id):
        self._last_folder_msg_path = self.msg_folder_path(folder_id)
        ret = self._get(self._last_folder_msg_path, referer=self.synergia_url_from_path("/rodzic/index"))
        inbox_html = ret.text
        soup = BeautifulSoup(inbox_html, "html.parser")
        lines0 = soup.find_all("tr", {"class": "line0"})
        lines1 = soup.find_all("tr", {"class": "line1"})
        msgs = []
        for msg in chain(lines0, lines1):
            all_a_elems = msg.find_all("a")
            if not all_a_elems:
                continue
            link = all_a_elems[0]["href"].strip()
            read = True
            for td in msg.find_all("td"):
                if "bold" in td.get("style", ""):
                    read = False
                    break
            msgs.append((link, read))
        msgs.reverse()
        return msgs

def to_msg_id(login, msg_path):
    msg_id_enc = base64.b64encode(f"{login} {msg_path}".encode()).decode()
    return f"<{msg_id_enc}@pylibrus>"

def to_login_and_id(msg_id_header: str):
    msg_id_txt, librus = msg_id_header.strip("<>").split("@", 1)
    if librus == "librus":
        login, msg_url = base64.b64decode(msg_id_txt.encode()).decode().split(" ", 1)
        return login, msg_url


class LibrusNotifier(object):
    def __init__(self, librus_user: LibrusUser, db_url):
        self._librus_user = librus_user
        self._engine = None
        self._session = None
        self._db_url = db_url

    def _create_db(self):
        self._engine = create_engine(self._db_url)
        Base.metadata.create_all(self._engine)
        session_maker = sessionmaker(bind=self._engine)
        self._session = session_maker()

    def __enter__(self):
        if self._librus_user.name:
            print(f" ------  {self._librus_user.name}  ------")
        self._create_db()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is None:
            if self._session:
                self._session.commit()
        else:
            self._session.rollback()

    def get_msg(self, url):
        return self._session.get(Msg, url)

    def add_msg(self, url, folder_id, sender, date, subject, contents_html, contents_text, attachments):
        msg = self.get_msg(url)
        if not msg:
            msg = Msg(
                url=url,
                folder=folder_id,
                sender=sender,
                date=date,
                subject=subject,
                contents_html=contents_html,
                contents_text=contents_text,
            )
            self._session.add(msg)
            self._session.flush()  # without that mysql may fail with "foreign key constraint fails"
            for attachment in attachments:
                attachment.msg_path = url
                self._session.add(attachment)
            self._session.flush()
        return msg

    def get_attachments(self, msg_from_db) -> list[Attachment]:
        return self._session.query(Attachment).filter(Attachment.msg_path == msg_from_db.url).all()

    def notify(self, msg_from_db: Msg, attachments: list[Attachment]):
        if self._librus_user.notify.is_webhook():
            print(f"Sending '{msg_from_db.subject}' to webhook from {msg_from_db.sender} ({msg_from_db.date})")
            self.send_via_webhook(msg_from_db, attachments=attachments)
        else:
            print(f"Sending '{msg_from_db.subject}' to {self._librus_user.notify.email_dest} from {msg_from_db.sender}")
            self.send_email(msg_from_db, attachments=attachments)

    def send_via_webhook(self, msg_from_db, attachments: list[Attachment]):
        attachments_name = []
        attachemnt_to_download_link = {attach.name: LibrusScraper.get_attachment_download_link(attach.link_id) for attach in attachments}
        for attach in attachments:
            attachments_name.append(attach.name)

        msg = dedent(f"""
        *LIBRUS {self._librus_user.name} - {msg_from_db.date}*
        *Od: {msg_from_db.sender}*
        *Temat: {msg_from_db.subject}*
        """) + f"\n{msg_from_db.contents_text}"
        if attachemnt_to_download_link:
            msg += "\n\nZałączniki:\n"
            for attachment_name, link in attachemnt_to_download_link.items():
                msg += f"- <{link}|{attachment_name}>\n"
        message = {
            'text': msg,
        }

        response = requests.post(
            self._librus_user.notify.webhook, data=json.dumps(message),
            headers={'Content-Type': 'application/json'}
        )

        if response.status_code != 200:
            print(f'Failed to send message. Status code: {response.status_code}')

    def send_email(self, msg_from_db: Msg, attachments: list[Attachment]):

        msg = EmailMessage()
        msg.set_charset("utf-8")

        subject = f"{self._librus_user.name} - {msg_from_db.subject}" if self._librus_user.name else msg_from_db.subject

        msg["Subject"] = subject
        msg["From"] = f"{msg_from_db.sender} <{self._librus_user.notify.smtp_user}>"
        msg["To"] = ", ".join(self._librus_user.notify.email_dest)
        msg["Message-ID"] = to_msg_id(self._librus_user.login, msg_from_db.url)

        attachments_only_with_link: list[Attachment] = []
        attachments_with_data: list[Attachment] = []
        for attach in attachments:
            if attach.data is None:
                attachments_only_with_link.append(attach)
            else:
                attachments_with_data.append(attach)
        attachments_as_text_msg = "" if not attachments_only_with_link else "\n\nZałączniki:\n" + "\n - ".join(LibrusScraper.get_attachment_download_link(att.link_id) for att in attachments_only_with_link)
        attachments_as_html_msg = "" if not attachments_only_with_link else "<br/><br/><p>Załączniki:<p><ul>" + "".join(f"<li><a href='{LibrusScraper.get_attachment_download_link(att.link_id)}'>{att.name}</a></li>" for att in attachments_only_with_link) + "</ul>"

        msg.set_content(msg_from_db.contents_text + attachments_as_text_msg)
        msg.add_alternative(msg_from_db.contents_html + attachments_as_html_msg, subtype='html')
        for attach in attachments_with_data:
            msg.add_attachment(attach.data, maintype='application', subtype='octet-stream', filename=attach.name)

        server = smtplib.SMTP(self._librus_user.notify.smtp_server, self._librus_user.notify.smtp_port)
        server.ehlo()
        server.starttls()
        server.login(self._librus_user.notify.smtp_user, self._librus_user.notify.smtp_pass)
        server.sendmail(self._librus_user.notify.smtp_user, self._librus_user.notify.email_dest, msg.as_string())
        server.close()


def read_pylibrus_config() -> tuple[PyLibrusConfig, list[LibrusUser]]:
    config = configparser.ConfigParser()
    if os.path.exists(CONFIG_FILE_PATH):
        print(f"Read config from file: {CONFIG_FILE_PATH}")
        config.read(CONFIG_FILE_PATH)

    env = dict(os.environ)
    pylibrus_config = PyLibrusConfig.read_config(config, env=env)
    librus_users = PyLibrusConfig.read_users(config, env=env)
    return pylibrus_config, librus_users

def debug(msg):
    global PYLIBRUS_CONFIG
    if PYLIBRUS_CONFIG.debug:
        print(msg)

def store_cookies_in_file(cookies_per_login: dict):
    with open(STORED_COOKIES_PATH, "w") as f:
        f.write(json.dumps(cookies_per_login))

def load_cookies_from_file():
    cookies_per_login = {}
    try:
        with open(STORED_COOKIES_PATH, "r") as f:
            cookies_per_login = json.loads(f.read())
    except Exception:
        pass
    return cookies_per_login


def main():
    global PYLIBRUS_CONFIG
    pylibrus_config, librus_users = read_pylibrus_config()
    PYLIBRUS_CONFIG = pylibrus_config
    print(f"Config: {PYLIBRUS_CONFIG}")
    for user in librus_users:
        print(f"User: {user}")

    test_notify = str_to_bool(os.environ.get("TEST_EMAIL_CONF")) or str_to_bool(os.environ.get("TEST_NOTIFY"))

    if test_notify:
        notifier = LibrusNotifier(librus_users[0], db_name=PYLIBRUS_CONFIG.db_name)
        msg = Msg(
                url="/wiadomosci/1/5/1000322/f0",
                folder="Odebrane",
                sender="Testing sender Żółta Jaźń [Nauczyciel]",
                date=datetime.datetime.now(),
                subject="Testing subject with żółta jaźć",
                contents_html="<h2>html content with żółta jażń</h2>",
                contents_text="text content with żółta jaźń",
            )
        print("Sending testing notify")
        notifier.notify(msg, [
            Attachment(
                link_id='1000322/8916574',
                msg_path='/wiadomosci/1/5/1000322/f0',
                name='Psiałóść na\n śŁÓŚFU$#!.pdf',
                data=b'Definitelly not valid PDF'
            )
        ])
        return 2

    cookies_per_login = load_cookies_from_file()

    for i, librus_user in enumerate(librus_users):
        with LibrusScraper(librus_user.login, librus_user.password, debug=PYLIBRUS_CONFIG.debug, cookies=cookies_per_login.get(librus_user.login)) as scraper:
            cookies_per_login[librus_user.login] = scraper._cookies
            with LibrusNotifier(librus_user, db_url=PYLIBRUS_CONFIG.db_url) as notifier:
                msgs = scraper.msgs_from_folder(PYLIBRUS_CONFIG.inbox_folder_id)
                for msg_path, read in msgs:
                    msg = notifier.get_msg(msg_path)

                    if not msg:
                        debug(f"Fetch {msg_path}")

                        fetch_attachment_content = PYLIBRUS_CONFIG.fetch_attachments and librus_user.notify.is_email()
                        msg_content_or_none = scraper.fetch_msg(msg_path, fetch_attachment_content)
                        if msg_content_or_none is None:
                            continue
                        sender, subject, date, contents_html, contents_text, attachments = msg_content_or_none
                        msg = notifier.add_msg(
                            msg_path, PYLIBRUS_CONFIG.inbox_folder_id, sender, date, subject, contents_html, contents_text, attachments
                        )

                    if PYLIBRUS_CONFIG.send_message == "unsent" and msg.email_sent:
                        print(f"Do not send '{msg.subject}' (message already sent)")
                    elif PYLIBRUS_CONFIG.send_message == "unread" and read:
                        print(f"Do not send '{msg.subject}' (message already read)")
                    else:
                        notifier.notify(msg, notifier.get_attachments(msg))
                        msg.email_sent = True
        if i != len(librus_users) - 1:
            time.sleep(PYLIBRUS_CONFIG.sleep_between_librus_users)
    store_cookies_in_file(cookies_per_login)

if __name__ == "__main__":
    sys.exit(main())
