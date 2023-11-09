import datetime
import json
import os
import shutil

import httpx
import ulid

import config

from pathlib import Path
from typing import Any, Self
from urllib.parse import urlparse

from sqlalchemy import Column, ForeignKey, Table, UniqueConstraint
from sqlalchemy import Dialect, TypeDecorator
from sqlalchemy import DECIMAL, DateTime, Integer, LargeBinary, String, Text
from sqlalchemy import ARRAY, JSON
from sqlalchemy import create_engine
from sqlalchemy import ScalarResult, Select, func, sql
from sqlalchemy.ext.mutable import MutableDict, MutableList
from sqlalchemy.orm import DeclarativeBase, Mapped
from sqlalchemy.orm import Session as _Session
from sqlalchemy.orm import mapped_column, relationship

from base.exception import *
from base.util import now, localtime, make_url, sha256_hmac


class Session(_Session):
    def count(self, queryset: Select) -> int:
        queryset = copy.copy(
            queryset.with_only_columns(
                func.count(queryset.selected_columns[0]),
            )
        )

        queryset._order_by_clauses = ()

        return self.scalar(queryset) or 0


class Base(DeclarativeBase):
    """
    模型
    """

    def __getattribute__(self, name: str) -> Any:
        """
        获取属性
        """

        value = object.__getattribute__(self, name)

        if isinstance(value, datetime.datetime):
            value = localtime(value).datetime

        return value

    def __setattr__(self, name: str, value: Any) -> None:
        """
        设置属性
        """

        if name in self.__table__.c.keys():
            column = self.__table__.c.get(name)

            if value is None:
                if column.default:
                    value = column.default.arg

                    if callable(value):
                        value = value(None)

            if isinstance(value, datetime.datetime):
                value = localtime(value).datetime
            elif isinstance(value, str):
                value = value.strip()

                if isinstance(column.type, String):
                    if column.type.length:
                        value = value[: column.type.length]

                    if not value:
                        if column.nullable:
                            value = None
            else:
                pass

            if hasattr(column.type, "make"):
                value = column.type.make(value)

        super().__setattr__(name, value)

    def dict(
        self,
        excludes: list[str] | None = None,
        exclude_foreignkey: bool = False,
        exclude_none: bool = False,
    ) -> dict:
        """
        转换为dict
        """

        data = {}

        for name, column in self.__table__.c.items():
            if excludes:
                if name in excludes:
                    continue

            if column.primary_key:
                continue

            if exclude_foreignkey:
                if column.foreign_keys:
                    continue

            value = getattr(self, name)

            if value is None:
                if not exclude_none:
                    data[name] = None

                continue

            if isinstance(column.type, ARRAY):
                if isinstance(column.type.item_type, ChoiceType):
                    choices = []

                    for choice in value:
                        choices.append(choice.dict())

                    value = choices

            if isinstance(value, StorageBaseType):
                value = value.path

            if isinstance(value, PasswordType):
                value = value.hash

            if hasattr(value, "dict"):
                value = value.dict()

            data[name] = value

        return data

    def from_data(
        self, data: dict, excludes: list[str] | None = None, exclude_none: bool = False
    ) -> None:
        """
        从dict更新
        """

        for name, column in self.__table__.c.items():
            if name not in data:
                continue

            if excludes:
                if name in excludes:
                    continue

            if column.foreign_keys:
                continue

            value = data.get(name)

            if value is None:
                if not exclude_none:
                    setattr(self, name, None)

                continue

            if isinstance(column.type, ARRAY):
                if isinstance(column.type.item_type, ChoiceType):
                    choices = []

                    for choice in value:
                        choices.append(column.type.item_type(choice))

                    value = choices

            if isinstance(value, str):
                value = value.strip()

            setattr(self, name, value)

    def validate_data(self, session: Session | None = None) -> None:
        """
        数据校验
        """

    @classmethod
    def subclasses(cls) -> list[Any]:
        """
        子类
        """

        data = []

        for x in cls.__subclasses__():
            if hasattr(x, "__tablename__"):
                data.append(x)

            if x.__subclasses__():
                data += x.subclasses()

        return data


class JSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime.datetime):
            return localtime(obj).format()
        elif isinstance(obj, datetime.date | datetime.time):
            return obj.isoformat()
        else:
            return json.JSONEncoder.default(self, obj)


# ----------------------------------------------------------
#
#                            Type
#
# ----------------------------------------------------------


JSONDict = MutableDict.as_mutable(JSON)


class ChoiceType(TypeDecorator):
    """
    Choice
    """

    impl = Integer()
    cache_ok = False

    def __init__(
        self, choices: tuple[int, str] | None = None, value: int | None = None, **kwargs
    ):
        self._choices = choices or tuple()

        self.code = None
        self.value = None

        choice = self.process_result_value(value)

        if choice:
            self.code = choice.code
            self.value = choice.value

        super().__init__(**kwargs)

    def __eq__(self, other: Self | int) -> bool:
        if isinstance(other, self.__class__):
            return (self._choices, self.code) == (other._choices, other.code)

        if isinstance(other, int):
            if self.code:
                return self.code == other

        return False

    def __lt__(self, other: Self | int) -> bool:
        if isinstance(other, self.__class__):
            if self._choices == other._choices:
                return self.code < other.code

        if isinstance(other, int):
            if self.code:
                return self.code < other

        return False

    def __le__(self, other: Self | int) -> bool:
        if isinstance(other, self.__class__):
            if self._choices == other._choices:
                return self.code <= other.code

        if isinstance(other, int):
            if self.code:
                return self.code <= other

        return False

    def __gt__(self, other: Self | int) -> bool:
        return not (self <= other)

    def __ge__(self, other: Self | int) -> bool:
        return not (self < other)

    def __hash__(self) -> int:
        return hash(self.code)

    def __repr__(self) -> str:
        if self.code:
            return f"ChoiceType({self.code}, {self.value})"
        else:
            return "ChoiceType()"

    def __str__(self) -> str:
        return str((self.code, self.value))

    def make(self, value: Any) -> Self | None:
        if isinstance(value, self.__class__):
            value = value.code

        return self.process_result_value(value)

    def dict(self) -> dict:
        return {"code": self.code, "value": self.value}

    def process_bind_param(self, value: Any, dialect: Dialect) -> int | None:
        return value.code

    def process_result_value(
        self, value: Any, dialect: Dialect | None = None
    ) -> Self | None:
        if isinstance(value, int):
            for _choice in self._choices:
                if _choice[0] == value:
                    choice = self.__class__(self._choices)

                    choice.code = _choice[0]
                    choice.value = _choice[1]

                    return choice

        return None


class PasswordType(TypeDecorator):
    """
    密码类型
    """

    impl = LargeBinary(512)
    cache_ok = False

    def __init__(self, hash: bytes | str | None = None, **kwargs: Any):
        from passlib.context import LazyCryptContext

        self.context = LazyCryptContext(schemes=["pbkdf2_sha512"])

        if isinstance(hash, bytes):
            self.hash = hash
        elif isinstance(hash, str):
            self.hash = self.context.hash(hash).encode()
        else:
            self.hash = None

        super().__init__(**kwargs)

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, bytes | None):
            return self.hash == other

        if isinstance(other, self.__class__):
            return self.hash == other.hash

        return self.context.verify(str(other), self.hash)

    def __hash__(self) -> int:
        return hash(self.hash)

    def __repr__(self) -> str:
        if self.hash:
            return f"PasswordType({self.hash})"
        else:
            return "PasswordType()"

    def __str__(self) -> str:
        return (self.hash or b"").decode()

    def make(self, value: Any) -> Self | None:
        if isinstance(value, self.__class__):
            value = value.hash

        return self.process_result_value(self.__class__(value).hash)

    def process_bind_param(self, value: Any, dialect: Dialect) -> bytes | None:
        if isinstance(value.hash, bytes):
            return value.hash

        return None

    def process_result_value(
        self, value: Any, dialect: Dialect | None = None
    ) -> Self | None:
        if isinstance(value, bytes):
            return self.__class__(value)

        return None


class StorageBaseType(String):
    """
    存储类型(基类)
    """

    def __init__(self, path: str | None = None, **kwargs: Any):
        self.session = kwargs.pop("session", None)
        self._path = path

        super().__init__(length=254)

    def make(self, value: Any) -> Self | None:
        if isinstance(value, self.__class__):
            value = value.path

        return self.process_result_value(value)

    def __str__(self) -> str:
        return self.path or ""

    def process_bind_param(self, value: Any, dialect: Dialect):
        return value.path

    def process_result_value(self, value: Any, dialect: Dialect | None = None):
        if isinstance(value, str):
            return self.__class__(value)

        return None

    @property
    def path(self) -> str | None:
        if isinstance(self._path, str):
            return urlparse(self._path).path.lstrip("/")

        return None

    @path.setter
    def path(self, path: str | None) -> None:
        self._path = path

    @property
    def url(self) -> str | None:
        return None

    def save(self, content: bytes) -> bool:
        """
        保存文件
        """

        return False

    def delete(self) -> bool:
        """
        删除文件
        """

        return True

    def content(self) -> bytes | None:
        """
        获取文件内容
        """

        return None

    @classmethod
    def content_from_url(cls, url: str) -> bytes | None:
        """
        从URL获取文件内容
        """

        return None

    def get_session(self) -> Any:
        """
        获取存储Session
        """

        return None


class StorageFileType(StorageBaseType):
    """
    存储类型(文件系统)
    """

    def __init__(self, path: str | None = None, **kwargs: Any):
        if hasattr(config, "STORAGE_DIR"):
            self.base_dir = getattr(config, "STORAGE_DIR")
        else:
            self.base_dir = config.BASE_DIR.joinpath("../storage").resolve()

        super().__init__(path, **kwargs)

    @property
    def url(self) -> str | None:
        accesskey = ulid.ulid()
        expires = localtime().shift(seconds=config.STORAGE_EXPIRED).int_timestamp
        signature = sha256_hmac(
            make_url(self.path, accesskey=accesskey, expires=expires)
        )

        return make_url(
            "{}{}".format("/storage/", self.path),
            accesskey=accesskey,
            expires=expires,
            signature=signature,
        )

    def save(self, content: bytes) -> bool:
        """
        保存文件
        """

        filename = self.base_dir.joinpath(self.path)

        try:
            filename.parent.mkdir(parents=True, exist_ok=True)

            with open(filename.as_posix(), "wb") as f:
                f.write(content)

            return True
        except Exception:
            pass

        return False

    def delete(self) -> bool:
        """
        删除文件
        """

        filename = self.base_dir.joinpath(self.path)

        try:
            if filename.is_file():
                os.remove(filename.as_posix())
            elif filename.is_dir():
                shutil.rmtree(filename.as_posix())
            else:
                pass

            return True
        except Exception:
            pass

        return False

    def content(self) -> bytes | None:
        """
        获取文件内容
        """

        filename = self.base_dir.joinpath(self.path)

        try:
            if filename.is_file():
                with open(filename.as_posix(), "rb") as f:
                    return f.read()
        except Exception:
            pass

        return None

    @classmethod
    def content_from_url(cls, url: str) -> bytes | None:
        """
        从URL获取文件内容
        """

        from urllib.parse import urlparse, parse_qsl

        r = urlparse(url)

        if r.path.startswith("/storage/"):
            path = r.path.removeprefix("/storage/")
            data = dict(parse_qsl(r.query))

            accesskey = data.get("accesskey", "")
            expires = data.get("expires", "")
            signature = data.get("signature", "")

            if signature != sha256_hmac(
                make_url(path, accesskey=accesskey, expires=expires)
            ):
                raise HTTPException(
                    detail="签名错误",
                    status_code=HTTP_400_BAD_REQUEST,
                )

            try:
                if now() > localtime(int(expires)):
                    raise HTTPException(
                        detail="签名过期",
                        status_code=HTTP_400_BAD_REQUEST,
                    )

                return cls(path).content()
            except Exception:
                raise HTTPException(
                    detail="签名错误",
                    status_code=HTTP_400_BAD_REQUEST,
                )

        return None


class StorageType(StorageFileType):
    """
    存储类型
    """


# ----------------------------------------------------------
#
#                           初始化
#
# ----------------------------------------------------------


engine = create_engine(
    config.DATABASE_URL,
    json_serializer=lambda obj: json.dumps(obj, cls=JSONEncoder),
    pool_pre_ping=True,
    pool_recycle=3600,
)
