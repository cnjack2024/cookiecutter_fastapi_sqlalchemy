import sys

from pathlib import Path

sys.path.append(Path(__file__).parent.parent.parent.as_posix())

import click
import jinja2

from base.util import snake_case
from config import BASE_DIR
from models import *


class Generate:
    @staticmethod
    def get_model(name: str) -> Base | None:
        """
        获取模型
        """

        model = None

        for x in Base.subclasses():
            if x.__name__ == name:
                model = x

                break

        return model

    @click.command("model")
    @click.argument("name")
    @click.argument("description")
    @staticmethod
    def model(name: str, description: str) -> None:
        """
        生成模型
        """

        STRING = '''
            from base.models import *


            class {{ name }}(Base):
                """
                {{ description }}
                """

                __tablename__ = "{{ tablename }}"

                id: Mapped[int] = mapped_column(primary_key=True, comment="ID")
                name: Mapped[str] = mapped_column(String(64), comment="名称")

                update_by: Mapped[str] = mapped_column(String(64), nullable=True, comment="更新人")
                update_time: Mapped[datetime.datetime] = mapped_column(
                    DateTime(timezone=True), onupdate=now, nullable=True, comment="更新时间"
                )
                create_by: Mapped[str] = mapped_column(String(64), comment="创建人")
                create_time: Mapped[datetime.datetime] = mapped_column(
                    DateTime(timezone=True), default=now, comment="创建时间"
                )
                description: Mapped[str] = mapped_column(Text, nullable=True, comment="备注")

                def validate_data(self, session: Session | None = None) -> None:
                    """
                    数据校验
                    """
        '''

        content = jinja2.Template(STRING).render(
            name=name, description=description, tablename=snake_case(name)
        )
        content = "\n".join([x[12:].rstrip() for x in content.splitlines()]).strip()

        click.echo(content)

    @click.command("relationship_model")
    @click.argument("model")
    @click.argument("secondary_model")
    @staticmethod
    def relationship_model(model: str, secondary_model: str) -> None:
        """
        生成关联模型
        """

        STRING = """
            {{ name }}_{{ secondary_name }} = Table(
                "{{ name }}_{{ secondary_name }}",
                Base.metadata,
                Column(
                    "{{ name }}_id",
                    ForeignKey("{{ name }}.id", ondelete="CASCADE"),
                    primary_key=True,
                    comment="{{ description }}",
                ),
                Column(
                    "{{ secondary_name }}_id",
                    ForeignKey("{{ secondary_name }}.id", ondelete="CASCADE"),
                    primary_key=True,
                    comment="{{ secondary_description }}",
                ),
            )
        """

        model_obj = Generate.get_model(model)

        if not model_obj:
            raise click.ClickException(f"未知模型: {model}")

        description = (model_obj.__doc__ or "").strip().splitlines()[0]

        secondary_model_obj = Generate.get_model(secondary_model)

        if not secondary_model_obj:
            raise click.ClickException(f"未知模型: {secondary_model}")

        secondary_description = (
            (secondary_model_obj.__doc__ or "").strip().splitlines()[0]
        )

        content = jinja2.Template(STRING).render(
            name=snake_case(model_obj.__name__),
            model=model_obj,
            description=description,
            secondary_name=snake_case(secondary_model_obj.__name__),
            secondary_model=secondary_model_obj,
            secondary_description=secondary_description,
        )
        content = "\n".join([x[12:].rstrip() for x in content.splitlines()]).strip()

        click.echo(content)

    @click.command("schema")
    @click.argument("model")
    @staticmethod
    def schema(model: str) -> None:
        """
        生成schema
        """

        def get_typename(type) -> str:
            """
            获取类型
            """

            if hasattr(type, "impl"):
                typename = type.impl.python_type.__name__

                if type.__class__.__name__ == "ChoiceType":
                    typename = "ChoiceModel"
            else:
                modulename = type.python_type.__module__
                typename = type.python_type.__name__

                if modulename in ("datetime", "decimal"):
                    typename = f"{modulename}.{typename}"

            if typename == "datetime.datetime":
                typename = "DateTimeType"

            if typename == "datetime.time":
                typename = "TimeType"

            return typename

        STRING = '''
            from base.schemas import *
            from models import *


            # ----------------------------------------------------------
            #
            # {{ prefix_description }}
            #
            # ----------------------------------------------------------


            class {{ model.__name__ }}PaginationModel(BaseModel):
                """
                {{ description }}分页信息
                """

                {% for name, typename, required, foreignkey, blank in info -%}
                {% if foreignkey -%}
                {% if required -%}
                {{ name.removesuffix("_id") }}: NameModel | None = None
                {%- else -%}
                {{ name.removesuffix("_id") }}: NameModel | None = None
                {%- endif %}
                {%- else -%}
                {% if required -%}
                {{ name }}: {{ typename }}
                {%- else -%}
                {{ name }}: {{ typename }} | None = None
                {%- endif %}
                {%- endif %}
                {% if blank %}
                {% endif %}
                {%- endfor %}
                def update(self, obj: Any) -> None:
                    """
                    更新数据
                    """

                    {% for name, required, foreignkey, description, blank in foreignkey_info -%}
                    {% if required -%}
                    self.{{ name.removesuffix("_id") }} = NameModel.from_obj(obj.{{ name.removesuffix("_id") }})
                    {%- else -%}
                    if obj.{{ name.removesuffix("_id") }}:
                        self.{{ name.removesuffix("_id") }} = NameModel.from_obj(obj.{{ name.removesuffix("_id") }})
                    {%- endif %}
                    {% if blank %}
                    {% endif %}
                    {%- endfor %}

            class {{ model.__name__ }}Model({{ model.__name__ }}PaginationModel):
                """
                {{ description }}信息
                """

                def update(self, obj: Any) -> None:
                    """
                    更新数据
                    """

                    super().update(obj)


            class {{ model.__name__ }}CreateModel(BaseModel):
                """
                新建{{ description }}
                """

                {% for name, typename, required, foreignkey, blank in update_info -%}
                {% if foreignkey -%}
                {% if required -%}
                {{ name }}: {{ typename }}
                {%- else -%}
                {{ name }}: {{ typename }} | None = None
                {%- endif %}
                {%- else -%}
                {% if required -%}
                {{ name }}: {{ typename }}
                {%- else -%}
                {{ name }}: {{ typename }} | None = None
                {%- endif %}
                {%- endif %}
                {% if blank %}
                {% endif %}
                {%- endfor %}
                def update(self, obj: Any, session: Session) -> None:
                    """
                    更新数据
                    """
                    {% for name, required, foreignkey, description, blank in foreignkey_info %}
                    {% if required -%}
                    {{ name }} = {{ foreignkey.__name__ }}.objects(id=self.{{ name }}).first()

                    if not {{ name }}:
                        raise HTTPException(
                            detail="未知{{ description }}",
                            status_code=HTTP_400_BAD_REQUEST,
                        )

                    obj.{{ name }} = {{ name }}
                    {%- else -%}
                    if self.{{ name }}:
                        {{ name.removesuffix("_id") }} = session.get({{ foreignkey.__name__ }}, self.{{ name }})

                        if not {{ name.removesuffix("_id") }}:
                            raise HTTPException(
                                detail="未知{{ description }}",
                                status_code=HTTP_400_BAD_REQUEST,
                            )

                        obj.{{ name.removesuffix("_id") }} = {{ name.removesuffix("_id") }}
                    {%- endif %}
                    {% endfor %}

            class {{ model.__name__ }}UpdateModel({{ model.__name__ }}CreateModel):
                """
                更新{{ description }}
                """

                def update(self, obj: Any) -> None:
                    """
                    更新数据
                    """

                    super().update(obj, obj._sa_instance_state.session)
        '''

        model_obj = Generate.get_model(model)

        if not model_obj:
            raise click.ClickException(f"未知模型: {model}")

        if not (model_obj.__doc__ or "").strip().splitlines():
            raise Exception("未填写模型注释, 生成失败")

        model_map = {}

        for x in Base.subclasses():
            model_map[x.__table__.name] = x

        fields = {}

        for name, column in model_obj.__table__.c.items():
            if column.type.__class__.__name__ in ("PasswordType",):
                continue

            typename = get_typename(column.type)
            required = not column.nullable
            foreignkey = None
            primarykey = column.primary_key

            if column.default or column.server_default:
                required = True

            if column.foreign_keys:
                foreignkey = model_map.get(
                    list(column.foreign_keys)[0].column.table.name
                )

            if hasattr(column.type, "item_type"):
                item_typename = get_typename(column.type.item_type)
                typename = f"{typename}[{item_typename}]"

            if typename:
                fields[name] = typename, required, foreignkey, primarykey

        info = []
        update_info = []
        foreignkey_info = []

        update_by = False

        for k, v in fields.items():
            typename, required, foreignkey, primarykey = v
            update_typename = typename.replace("ChoiceModel", "int")

            if k in ("create_by", "create_time", "update_by", "update_time"):
                if not update_by:
                    if info:
                        info[-1][-1] = True

                    if update_info:
                        update_info[-1][-1] = True

                update_by = True
            else:
                if update_by:
                    if info:
                        info[-1][-1] = True

                    if update_info:
                        update_info[-1][-1] = True

                update_by = False

            info.append([k, typename, required, foreignkey, False])

            if not primarykey and not update_by:
                update_info.append([k, update_typename, required, foreignkey, False])

            if not primarykey and foreignkey:
                if foreignkey_info:
                    if not foreignkey_info[-1][1]:
                        foreignkey_info[-1][-1] = True
                    else:
                        if not required:
                            foreignkey_info[-1][-1] = True

                description = (foreignkey.__doc__ or "").strip().splitlines()[0]
                foreignkey_info.append([k, required, foreignkey, description, False])

        if info:
            info[-1][-1] = False

        if update_info:
            update_info[-1][-1] = False

        description = (model_obj.__doc__ or "").strip().splitlines()[0]
        prefix_description = " " * ((58 - len(description)) // 2) + description

        content = jinja2.Template(STRING).render(
            model=model_obj,
            info=info,
            update_info=update_info,
            foreignkey_info=foreignkey_info,
            description=description,
            prefix_description=prefix_description,
        )

        content = "\n".join([x[12:].rstrip() for x in content.splitlines()]).strip()

        click.echo(content)

    @click.command("init_app")
    @click.argument("name")
    @click.argument("model")
    @staticmethod
    def init_app(name: str, model: str) -> None:
        """
        初始化app
        """

        def init_app(dirname: Path) -> None:
            """
            初始化
            """

            dirname.joinpath("api").mkdir(parents=True, exist_ok=True)
            dirname.joinpath("schemas").mkdir(parents=True, exist_ok=True)

            STRING = """
                from fastapi import APIRouter

                from . import login
                from . import info
                from . import upload


                app = APIRouter()


                app.include_router(login.app, tags=["登录"])
                app.include_router(info.app, tags=["用户信息"])
                app.include_router(upload.app, tags=["上传文件"])
            """

            content = jinja2.Template(STRING).render()
            content = "\n".join([x[16:].rstrip() for x in content.splitlines()]).strip()

            with open(
                dirname.joinpath("api").joinpath("__init__.py").as_posix(), "w"
            ) as f:
                f.write(content + "\n")

            STRING = """
                from base.schemas import *

                from .info import *
            """

            content = jinja2.Template(STRING).render()
            content = "\n".join([x[16:].rstrip() for x in content.splitlines()]).strip()

            with open(
                dirname.joinpath("schemas").joinpath("__init__.py").as_posix(), "w"
            ) as f:
                f.write(content + "\n")

            STRING = '''
                from base.schemas import *
                from models import *


                # ----------------------------------------------------------
                #
                #                          用户信息
                #
                # ----------------------------------------------------------


                class UserInfoModel(BaseModel):
                    """
                    用户信息
                    """

                    id: str
                    username: str

                    def update(self, obj: Any) -> None:
                        """
                        更新数据
                        """


                class UserInfoUpdateModel(BaseModel):
                    """
                    用户更新信息
                    """

                    username: str

                    def update(self, obj: Any) -> None:
                        """
                        更新数据
                        """
            '''

            content = jinja2.Template(STRING).render()
            content = "\n".join([x[16:].rstrip() for x in content.splitlines()]).strip()

            with open(
                dirname.joinpath("schemas").joinpath("info.py").as_posix(), "w"
            ) as f:
                f.write(content + "\n")

            STRING = """
                from base.app import init_app, init_api

                from . import api


                {{ app }} = init_app()
                {{ app }}.include_router(api.app)

                init_api({{ app }})
            """

            content = jinja2.Template(STRING).render(app=dirname.name)
            content = "\n".join([x[16:].rstrip() for x in content.splitlines()]).strip()

            with open(dirname.joinpath("__init__.py").as_posix(), "w") as f:
                f.write(content + "\n")

            STRING = """
                {% for app in apps -%}
                from .{{ app }} import {{ app }}
                {% endfor %}
            """

            apps = []

            for x in dirname.joinpath("..").iterdir():
                if x.is_dir():
                    if x.name.startswith(".") or x.name.startswith("_"):
                        continue

                    apps.append(x.name)

            content = jinja2.Template(STRING).render(apps=sorted(apps))
            content = "\n".join([x[16:].rstrip() for x in content.splitlines()]).strip()

            with open(dirname.joinpath("..", "__init__.py").as_posix(), "w") as f:
                f.write(content + "\n")

        def init_app_info(dirname: Path, name: str, model_obj: Base) -> None:
            """
            用户信息
            """

            STRING = '''
                """
                用户信息
                """

                from fastapi import APIRouter, Request

                from base.app import limiter
                from base.auth import authentication
                from base.exception import *

                from app.{{ app }}.schemas import *


                app = APIRouter()


                class UserInfoAPI(Request):
                    @app.get(
                        "/info",
                        response_model=UserInfoModel,
                        summary="获取用户信息",
                    )
                    async def info(request: Request) -> UserInfoModel:
                        """
                        获取用户信息
                        """

                        auth_user = authentication(request.user, "{{ app }}")

                        with Session(engine) as session, session.begin():
                            session.add(auth_user)

                            response_model = UserInfoModel.from_obj(auth_user)
                            response_model.update(auth_user)

                        return response_model

                    @app.put(
                        "/update",
                        response_model=SuccessModel,
                        summary="更新用户信息",
                    )
                    async def update(request: Request, data: UserInfoUpdateModel) -> SuccessModel:
                        """
                        更新用户信息
                        """

                        auth_user = authentication(request.user, "{{ app }}")

                        with Session(engine) as session, session.begin():
                            session.add(auth_user)

                            auth_user.from_data(data.dict())
                            data.update(auth_user)

                            auth_user.validate_data()

                            session.add(auth_user)

                        return SuccessModel()
            '''

            if name in ("admin",):
                STRING += '''
                    @app.get(
                        "/menu",
                        response_model=ListModel,
                        summary="菜单列表",
                    )
                    async def menu(request: Request) -> ListModel:
                        """
                        菜单列表
                        """

                        auth_user = authentication(request.user, "{{ app }}")

                        with Session(engine) as session, session.begin():
                            session.add(auth_user)

                            response_model = ListModel()
                            response_model.update()

                        return response_model
                '''

            content = jinja2.Template(STRING).render(app=name, model=model_obj)
            content = "\n".join([x[16:].rstrip() for x in content.splitlines()]).strip()

            with open(dirname.joinpath("info.py").as_posix(), "w") as f:
                f.write(content + "\n")

        def init_app_login(dirname: Path, name: str, model_obj: Base) -> None:
            """
            登录
            """

            STRING = '''
                """
                登录
                """

                import hashlib

                from fastapi import APIRouter, Request

                from base.app import limiter
                from base.auth import authentication
                from base.exception import *
                from base.redis import Redis
                from base.util import decode_aes, make_token

                from app.{{ app }}.schemas import *


                app = APIRouter()


                class LoginAPI(Request):
                    @app.post(
                        "/login",
                        response_model=LoginSuccessModel,
                        summary="登录",
                    )
                    @limiter.limit("1 per 10 second")
                    async def login(
                        request: Request, data: PasswordLoginArgsModel
                    ) -> LoginSuccessModel:
                        """
                        登录
                        """

                        with Session(engine) as session, session.begin():
                            auth_user = session.scalar(
                                sql.select({{ model.__name__ }}).where({{ model.__name__ }}.username == data.username)
                            )

                            if not auth_user:
                                raise HTTPException(
                                    detail="账号未授权",
                                    status_code=HTTP_400_BAD_REQUEST,
                                )

                            if not auth_user.enable:
                                raise HTTPException(
                                    detail="账号未启用",
                                    status_code=HTTP_400_BAD_REQUEST,
                                )

                            password = decode_aes(data.password)

                            if (not password) or auth_user.password != password:
                                raise HTTPException(
                                    detail="密码错误",
                                    status_code=HTTP_400_BAD_REQUEST,
                                )

                            token = make_token(str(auth_user.id), "{{ app }}")

                            with Redis() as conn:
                                conn.set(
                                    hashlib.sha256(token.encode()).hexdigest(),
                                    str(auth_user.id),
                                    30 * 60,
                                )

                        return LoginSuccessModel(token=token)

                    @app.post(
                        "/logout",
                        response_model=SuccessModel,
                        summary="退出",
                    )
                    @limiter.limit("1 per 10 second")
                    async def logout(request: Request) -> SuccessModel:
                        """
                        退出
                        """

                        auth_user = authentication(request.user, "{{ app }}")

                        with Redis() as conn:
                            conn.delete(request.user.token_hexdigest())

                        return SuccessModel()
            '''

            content = jinja2.Template(STRING).render(app=name, model=model_obj)
            content = "\n".join([x[16:].rstrip() for x in content.splitlines()]).strip()

            with open(dirname.joinpath("login.py").as_posix(), "w") as f:
                f.write(content + "\n")

        def init_app_upload(dirname: Path, name: str) -> None:
            """
            上传文件
            """

            STRING = '''
                """
                上传文件
                """

                import puremagic

                from io import BytesIO

                from fastapi import APIRouter, Request, UploadFile
                from PIL import Image

                from base.app import limiter
                from base.auth import authentication
                from base.exception import *

                from app.{{ app }}.schemas import *


                app = APIRouter()


                class UploadAPI(Request):
                    @app.post(
                        "/upload",
                        response_model=FileModel,
                        summary="上传文件",
                    )
                    @limiter.limit("1 per 10 second")
                    async def upload(request: Request, file: UploadFile) -> FileModel:
                        """
                        上传文件
                        """

                        auth_user = authentication(request.user, "{{ app }}")

                        try:
                            content = await file.read()
                        except BaseException:
                            raise HTTPException(
                                detail="读取文件失败",
                                status_code=HTTP_400_BAD_REQUEST,
                            )

                        filename = request.query_params.get("filename")

                        if not filename:
                            filename = (
                                Path("upload")
                                .joinpath(
                                    localtime().format("YYYYMMDD"),
                                    Path(ulid.ulid()).with_suffix(Path(file.filename).suffix),
                                )
                                .as_posix()
                            )

                        try:
                            for x in puremagic.magic_string(content):
                                if x.mime_type.startswith("image/"):
                                    ios = BytesIO()

                                    image = Image.open(BytesIO(content))
                                    image.save(ios, "webp")

                                    ios.seek(0)
                                    content = ios.read()

                                    filename = Path(filename).with_suffix(".webp").as_posix()

                                    break
                        except Exception:
                            pass

                        storage = StorageType(filename)

                        if not storage.save(content):
                            raise HTTPException(
                                detail="上传文件失败",
                                status_code=HTTP_400_BAD_REQUEST,
                            )

                        return FileModel(path=storage.url)
            '''

            content = jinja2.Template(STRING).render(app=name)
            content = "\n".join([x[16:].rstrip() for x in content.splitlines()]).strip()

            with open(dirname.joinpath("upload.py").as_posix(), "w") as f:
                f.write(content + "\n")

        model_obj = Generate.get_model(model)

        if not model_obj:
            raise click.ClickException(f"未知模型: {model}")

        dirname = Path(BASE_DIR).joinpath("app", name)

        init_app(dirname)
        init_app_info(dirname.joinpath("api"), name, model_obj)
        init_app_login(dirname.joinpath("api"), name, model_obj)
        init_app_upload(dirname.joinpath("api"), name)

    @click.command("crud")
    @click.argument("app")
    @click.argument("model")
    @click.argument("deletes", required=False)
    @click.argument("queryset", required=False)
    @click.argument("permission", required=False)
    @staticmethod
    def crud(
        app: str,
        model: str = None,
        deletes: bool = False,
        queryset: bool = False,
        permission: bool = False,
    ) -> None:
        """
        生成crud
        """

        STRING = '''
            """
            {{ description }}
            """

            from fastapi import APIRouter, Request

            from base.app import limiter
            from base.auth import authentication
            from base.exception import *

            from app.{{ app }}.schemas import *


            app = APIRouter()


            class {{ model.__name__ }}API(Request):
                {% if queryset -%}
                @staticmethod
                def queryset(queryset: Select, data: dict, kwargs: str | None = None) -> Select:
                    """
                    设置查询条件
                    """

                    kwargs = str(kwargs or "").strip()

                    if kwargs:
                        pass

                    return queryset

                {% endif -%}
                @app.get(
                    "/{{ prefix }}",
                    response_model=PaginationModel,
                    summary="{{ description }}分页列表",
                )
                async def list(
                    request: Request, page: int = 1, limit: int = 10, kwargs: str | None = None
                ) -> PaginationModel:
                    """
                    {{ description }}分页列表
                    """

                    {% if permission -%}
                    auth_user = authentication(request.user, "{{ app }}", True)
                    {% else -%}
                    auth_user = authentication(request.user, "{{ app }}")
                    {% endif %}
                    input_model = PaginationArgsModel(page=page, limit=limit)
                    response_model = PaginationModel()

                    with Session(engine) as session, session.begin():
                        session.add(auth_user)

                        queryset = sql.select({{ model.__name__ }})
                        {% if queryset -%}
                        queryset = {{ model.__name__ }}API.queryset(queryset, request.query_params, kwargs)
                        {% endif %}
                        response_model.init(session, queryset, input_model._limit())

                        for obj in input_model.queryset(
                            session, queryset.order_by({{ model.__name__ }}.{{ primarykey }}.desc())
                        ):
                            model = {{ model.__name__ }}PaginationModel.from_obj(obj)
                            model.update(obj)

                            response_model.data.append(model)

                    return response_model

                @app.get(
                    "/{{ prefix }}/{id:int}",
                    response_model={{ model.__name__ }}Model,
                    summary="获取{{ description }}信息",
                )
                async def get(request: Request, id: int) -> {{ model.__name__ }}Model:
                    """
                    获取{{ description }}信息
                    """

                    {% if permission -%}
                    auth_user = authentication(request.user, "{{ app }}", True)
                    {% else -%}
                    auth_user = authentication(request.user, "{{ app }}")
                    {% endif %}
                    with Session(engine) as session, session.begin():
                        session.add(auth_user)

                        obj = session.get({{ model.__name__ }}, id)

                        if not obj:
                            raise HTTPException(
                                detail="未知{{ description }}",
                                status_code=HTTP_400_BAD_REQUEST,
                            )

                        response_model = {{ model.__name__ }}Model.from_obj(obj)
                        response_model.update(obj)

                    return response_model

                @app.post(
                    "/{{ prefix }}",
                    response_model=SuccessModel,
                    summary="新建{{ description }}",
                )
                @limiter.limit("1 per 10 second")
                async def create_{{ model.__name__.lower() }}(
                    request: Request, data: {{ model.__name__ }}CreateModel
                ) -> SuccessModel:
                    """
                    新建{{ description }}
                    """

                    {% if permission -%}
                    auth_user = authentication(request.user, "{{ app }}", True)
                    {% else -%}
                    auth_user = authentication(request.user, "{{ app }}")
                    {% endif %}
                    with Session(engine) as session, session.begin():
                        session.add(auth_user)

                        {% if create_by -%}
                        obj = {{ model.__name__ }}(create_by=auth_user.name)
                        {% else -%}
                        obj = {{ model.__name__ }}()
                        {% endif %}
                        obj.from_data(data.dict())
                        data.update(obj)

                        obj.validate_data()

                        session.add(obj)

                    return SuccessModel()

                @app.put(
                    "/{{ prefix }}/{id:int}",
                    response_model=SuccessModel,
                    summary="更新{{ description }}",
                )
                async def update(
                    request: Request, id: int, data: {{ model.__name__ }}UpdateModel
                ) -> SuccessModel:
                    """
                    更新{{ description }}
                    """

                    {% if permission -%}
                    auth_user = authentication(request.user, "{{ app }}", True)
                    {% else -%}
                    auth_user = authentication(request.user, "{{ app }}")
                    {% endif %}
                    with Session(engine) as session, session.begin():
                        session.add(auth_user)

                        obj = session.get({{ model.__name__ }}, id)

                        if not obj:
                            raise HTTPException(
                                detail="未知{{ description }}",
                                status_code=HTTP_400_BAD_REQUEST,
                            )
                        {%- if update_by %}

                        obj.update_by = auth_user.name
                        obj.update_time = now()
                        {%- endif %}

                        obj.from_data(data.dict())
                        data.update(obj)

                        obj.validate_data()

                        session.add(obj)

                    return SuccessModel()

                {% if deletes -%}
                @app.delete(
                    "/{{ prefix }}",
                    response_model=SuccessModel,
                    summary="删除{{ description }}",
                )
                async def delete(request: Request, ids: List[int]) -> SuccessModel:
                    """
                    删除{{ description }}
                    """

                    {% if permission -%}
                    auth_user = authentication(request.user, "{{ app }}", True)
                    {% else -%}
                    auth_user = authentication(request.user, "{{ app }}")
                    {% endif %}
                    with Session(engine) as session, session.begin():
                        session.add(auth_user)

                        session.delete(sql.select({{ model.__name__ }}).where({{ model.__name__ }}.{{ primarykey }}.in_(ids)))

                    return SuccessModel()
                {% else -%}
                    @app.delete(
                    "/{{ prefix }}/{id:int}",
                    response_model=SuccessModel,
                    summary="删除{{ description }}",
                )
                async def delete(request: Request, id: int) -> SuccessModel:
                    """
                    删除{{ description }}
                    """

                    {% if permission -%}
                    auth_user = authentication(request.user, "{{ app }}", True)
                    {% else -%}
                    auth_user = authentication(request.user, "{{ app }}")
                    {% endif %}
                    with Session(engine) as session, session.begin():
                        session.add(auth_user)

                        session.delete(sql.select({{ model.__name__ }}).where({{ model.__name__ }}.{{ primarykey }} == id))

                    return SuccessModel()
                {%- endif %}
        '''

        model_obj = Generate.get_model(model)

        if not model_obj:
            raise click.ClickException(f"未知模型: {model}")

        if not (model_obj.__doc__ or "").strip().splitlines():
            raise Exception("未填写模型注释, 生成失败")

        description = (model_obj.__doc__ or "").strip().splitlines()[0]
        prefix = snake_case(model_obj.__name__)

        if app in ("admin",):
            permission = True

        primarykey = "id"

        for name, column in model_obj.__table__.c.items():
            if column.primary_key:
                primarykey = name

                break

        update_by = hasattr(model_obj, "update_by")
        create_by = hasattr(model_obj, "create_by")

        content = jinja2.Template(STRING).render(
            app=app,
            model=model_obj,
            prefix=prefix,
            description=description,
            deletes=deletes,
            queryset=queryset,
            permission=permission,
            primarykey=primarykey,
            update_by=update_by,
            create_by=create_by,
        )

        content = "\n".join([x[12:].rstrip() for x in content.splitlines()]).strip()

        click.echo(content)

    @click.command("choice")
    @click.argument("app")
    @click.argument("model")
    @staticmethod
    def choice(app: str, model: str) -> None:
        """
        生成choice
        """

        STRING = '''
            class {{ model.__name__ }}ChoiceAPI(Request):
                {% for choice in choices -%}
                @app.get(
                    "/{{ prefix }}/choice/{{ choice.name }}",
                    response_model=ListModel,
                    summary="{{ choice.comment or "" }}列表",
                )
                async def choice_{{ choice.name }}(request: Request) -> ListModel:
                    """
                    {{ choice.comment or "" }}列表
                    """

                    auth_user = authentication(request.user, "{{ app }}")

                    response_model = ListModel()

                    for choice in {{ model.__name__ }}.{{ choice.name  }}._choices:
                        model = ChoiceModel.from_obj(choice)
                        response_model.data.append(model)

                    response_model.update()

                    return response_model

                {% endfor -%}
        '''

        model_obj = Generate.get_model(model)

        if not model_obj:
            raise click.ClickException(f"未知文档: {model}")

        choices = []

        for name, column in model_obj.__table__.c.items():
            if isinstance(column.type, ChoiceType):
                choices.append(column)

        if choices:
            prefix = snake_case(model_obj.__name__)

            if app in ("admin",):
                permission = True

            content = jinja2.Template(STRING).render(
                app=app, model=model_obj, choices=choices, prefix=prefix
            )
            content = "\n".join([x[12:].rstrip() for x in content.splitlines()]).strip()

            click.echo(content)

    @click.command("foreignkey")
    @click.argument("app")
    @click.argument("model")
    @staticmethod
    def foreignkey(app: str, model: str) -> None:
        """
        生成foreignkey
        """

        STRING = '''
            class {{ model.__name__ }}ForeignKeyAPI(Request):
                {% for foreignkey, column in foreignkeys.items() -%}
                @app.get(
                    "/{{ prefix }}/foreignkey/{{ column.name.removesuffix("_id") }}",
                    response_model=ListModel,
                    summary="{{ column.comment or "" }}列表",
                )
                async def foreignkey_{{ column.name.removesuffix("_id") }}(request: Request) -> ListModel:
                    """
                    {{ column.comment or "" }}列表
                    """

                    auth_user = authentication(request.user, "{{ app }}")

                    response_model = ListModel()

                    with Session(engine) as session, session.begin():
                        session.add(auth_user)

                        queryset = sql.select({{ foreignkey.__name__ }})

                        for obj in queryset.order_by({{ foreignkey.__name__ }}.id):
                            model = NameModel.from_obj(obj)
                            response_model.data.append(model)

                        response_model.update()

                    return response_model

                {% endfor -%}
        '''

        model_obj = Generate.get_model(model)

        if not model_obj:
            raise click.ClickException(f"未知模型: {model}")

        model_map = {}

        for x in Base.subclasses():
            model_map[x.__table__.name] = x

        foreignkeys = {}

        for name, column in model_obj.__table__.c.items():
            if column.foreign_keys:
                foreignkey = model_map.get(
                    list(column.foreign_keys)[0].column.table.name
                )
                foreignkeys[foreignkey] = column

        if foreignkeys:
            prefix = snake_case(model_obj.__name__)

            if app in ("admin",):
                permission = True

            content = jinja2.Template(STRING).render(
                app=app, model=model_obj, foreignkeys=foreignkeys, prefix=prefix
            )
            content = "\n".join([x[12:].rstrip() for x in content.splitlines()]).strip()

            click.echo(content)

    @click.command("relationship")
    @click.argument("app")
    @click.argument("model")
    @click.argument("secondary_model")
    @click.argument("permission", required=False)
    @staticmethod
    def relationship(
        app: str, model: str, secondary_model: str, permission: bool = False
    ) -> None:
        """
        生成relationship
        """

        STRING = '''
            class {{ model.__name__ }}{{ secondary_model.__name__ }}API(Request):
                @app.get(
                    "/{{ prefix }}/{id:int}/relationship/{{ secondary_name }}/exists",
                    response_model=PaginationModel,
                    summary="已选{{ description }}关联{{ secondary_description }}分页列表",
                )
                async def exists(
                    request: Request, id: int, page: int = 1, limit: int = 10, kwargs: str = None
                ) -> PaginationModel:
                    """
                    已选{{ description }}关联{{ secondary_description }}分页列表
                    """

                    {% if permission -%}
                    auth_user = authentication(request.user, "{{ app }}", True)
                    {% else -%}
                    auth_user = authentication(request.user, "{{ app }}")
                    {% endif %}
                    input_model = PaginationArgsModel(page=page, limit=limit)
                    response_model = PaginationModel()

                    with Session(engine) as session, session.begin():
                        session.add(auth_user)

                        obj = session.get({{ model.__name__ }}, id)

                        if not obj:
                            raise HTTPException(
                                detail="未知{{ description }}",
                                status_code=HTTP_400_BAD_REQUEST,
                            )

                        sub_queryset = sql.select({{ name }}_{{ secondary_name }}.c.{{ secondary_name }}_id).where(
                            {{ name }}_{{ secondary_name }}.c.{{ name }}_id == id
                        )
                        queryset = sql.select({{ secondary_model.__name__ }}).where({{ secondary_model.__name__ }}.id.in_(sub_queryset))

                        kwargs = str(kwargs or "").strip()

                        if kwargs:
                            pass

                        response_model.init(session, queryset, input_model._limit())

                        for relationship_obj in input_model.queryset(
                            session, queryset.order_by({{ secondary_model.__name__ }}.id)
                        ):
                            model = {{ model.__name__ }}{{ secondary_model.__name__ }}PaginationModel.from_obj(relationship_obj)
                            model.update(relationship_obj.{{ secondary_name }})

                            response_model.data.append(model)

                    return response_model

                @app.get(
                    "/{{ prefix }}/{id:int}/relationship/{{ secondary_name }}/remaining",
                    response_model=PaginationModel,
                    summary="未选{{ description }}关联{{ secondary_description }}分页列表",
                )
                async def remaining(
                    request: Request, id: int, page: int = 1, limit: int = 10, kwargs: str = None
                ) -> PaginationModel:
                    """
                    未选{{ description }}关联{{ secondary_description }}分页列表
                    """

                    {% if permission -%}
                    auth_user = authentication(request.user, "{{ app }}", True)
                    {% else -%}
                    auth_user = authentication(request.user, "{{ app }}")
                    {% endif %}
                    input_model = PaginationArgsModel(page=page, limit=limit)
                    response_model = PaginationModel()

                    with Session(engine) as session, session.begin():
                        session.add(auth_user)

                        obj = session.get({{ model.__name__ }}, id)

                        if not obj:
                            raise HTTPException(
                                detail="未知{{ description }}",
                                status_code=HTTP_400_BAD_REQUEST,
                            )

                        sub_queryset = sql.select({{ name }}_{{ secondary_name }}.c.{{ secondary_name }}_id).where(
                            {{ name }}_{{ secondary_name }}.c.{{ name }}_id == id
                        )
                        queryset = sql.select({{ secondary_model.__name__ }}).where({{ secondary_model.__name__ }}.id.not_in(sub_queryset))

                        kwargs = str(kwargs or "").strip()

                        if kwargs:
                            pass

                        response_model.init(session, queryset, input_model._limit())

                        for relationship_obj in input_model.queryset(
                            session, queryset.order_by({{ secondary_model.__name__ }}.id)
                        ):
                            model = {{ model.__name__ }}{{ secondary_model.__name__ }}PaginationModel.from_obj(relationship_obj)
                            model.update(relationship_obj.{{ secondary_name }})

                            response_model.data.append(model)

                    return response_model

                @app.post(
                    "/{{ prefix }}/{id:int}/relationship/{{ secondary_name }}/add",
                    response_model=SuccessModel,
                    summary="新增{{ description }}关联{{ secondary_description }}",
                )
                async def add(request: Request, id: int, ids: List[int]) -> SuccessModel:
                    """
                    新增{{ description }}关联{{ secondary_description }}
                    """

                    {% if permission -%}
                    auth_user = authentication(request.user, "{{ app }}", True)
                    {% else -%}
                    auth_user = authentication(request.user, "{{ app }}")
                    {% endif %}
                    with Session(engine) as session, session.begin():
                        session.add(auth_user)

                        obj = session.get({{ model.__name__ }}, id)

                        if not obj:
                            raise HTTPException(
                                detail="未知{{ description }}",
                                status_code=HTTP_400_BAD_REQUEST,
                            )

                        queryset = sql.select({{ secondary_model.__name__ }}).where(id.in_(ids))

                        for relationship_obj in queryset.order_by(queryset.order_by({{ secondary_model.__name__ }}.id)):
                            obj.{{ secondary_name }}.append(relationship_obj)

                        session.add(obj)

                    return SuccessModel()

                @app.delete(
                    "/{{ prefix }}/{id:int}/relationship/{{ secondary_name }}/delete",
                    response_model=SuccessModel,
                    summary="删除{{ description }}关联{{ secondary_description }}",
                )
                async def delete(request: Request, id: int, ids: List[int]) -> SuccessModel:
                    """
                    删除{{ description }}关联{{ secondary_description }}
                    """

                    {% if permission -%}
                    auth_user = authentication(request.user, "{{ app }}", True)
                    {% else -%}
                    auth_user = authentication(request.user, "{{ app }}")
                    {% endif %}
                    with Session(engine) as session, session.begin():
                        session.add(auth_user)

                        session.delete(
                            sql.select({{ name }}_{{ secondary_name }}).where(
                                {{ name }}_{{ secondary_name }}.c.{{ name }}_id == id,
                                {{ name }}_{{ secondary_name }}.c.{{ secondary_name }}_id.in_(ids),
                            )
                        )

                    return SuccessModel()
        '''

        model_obj = Generate.get_model(model)

        if not model_obj:
            raise click.ClickException(f"未知模型: {model}")

        if not (model_obj.__doc__ or "").strip().splitlines():
            raise Exception("未填写模型注释, 生成失败")

        description = (model_obj.__doc__ or "").strip().splitlines()[0]

        secondary_model_obj = Generate.get_model(secondary_model)

        if not secondary_model_obj:
            raise click.ClickException(f"未知模型: {secondary_model}")

        if not (secondary_model_obj.__doc__ or "").strip().splitlines():
            raise Exception("未填写模型注释, 生成失败")

        secondary_description = (
            (secondary_model_obj.__doc__ or "").strip().splitlines()[0]
        )

        prefix = snake_case(model_obj.__name__)

        if app in ("admin",):
            permission = True

        content = jinja2.Template(STRING).render(
            app=app,
            name=snake_case(model_obj.__name__),
            model=model_obj,
            description=description,
            secondary_model=secondary_model_obj,
            secondary_description=secondary_description,
            secondary_name=snake_case(secondary_model_obj.__name__),
            prefix=prefix,
            permission=permission,
        )

        content = "\n".join([x[12:].rstrip() for x in content.splitlines()]).strip()

        click.echo(content)

    @click.group()
    @staticmethod
    def command():
        pass

    command.add_command(model)
    command.add_command(relationship_model)
    command.add_command(schema)
    command.add_command(init_app)
    command.add_command(crud)
    command.add_command(choice)
    command.add_command(foreignkey)
    command.add_command(relationship)


if __name__ == "__main__":
    Generate.command()
