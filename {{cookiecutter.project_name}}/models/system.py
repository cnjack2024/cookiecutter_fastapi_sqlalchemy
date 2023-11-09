import casbin

from base.models import *
from base.redis import Redis


class Menu(Base):
    """
    菜单
    """

    __tablename__ = "menu"

    id: Mapped[int] = mapped_column(primary_key=True, comment="ID")
    scope: Mapped[str] = mapped_column(String(64), default="admin", comment="SCOPE")
    name: Mapped[str] = mapped_column(String(64), comment="菜单名称")
    code: Mapped[str] = mapped_column(
        String(64), unique=True, index=True, comment="菜单代码"
    )
    path: Mapped[str] = mapped_column(String(128), comment="菜单路径")
    title: Mapped[str] = mapped_column(String(64), comment="菜单标题")
    icon: Mapped[str] = mapped_column(String(64), nullable=True, comment="菜单图标")
    prefix: Mapped[str] = mapped_column(String(254), nullable=True, comment="关联API前缀")

    __table_args__ = (
        UniqueConstraint("scope", "name"),
        UniqueConstraint("scope", "path"),
    )

    def validate_data(self, session: Session | None = None) -> None:
        """
        数据校验
        """

        if not self.code:
            raise HTTPException(
                detail="菜单代码不能为空",
                status_code=HTTP_400_BAD_REQUEST,
            )

        if len(self.code) % 4 != 0:
            raise HTTPException(
                detail="菜单代码长度错误(长度必须是4的倍数)",
                status_code=HTTP_400_BAD_REQUEST,
            )

        obj = session.scalar(sql.select(Menu).where(Menu.code == self.code))

        if obj and obj.id != self.id:
            raise HTTPException(
                detail="菜单代码已存在",
                status_code=HTTP_400_BAD_REQUEST,
            )

        if len(self.code) > 4:
            obj = session.scalar(sql.select(Menu).where(Menu.code == self.code[:-4]))

            if not obj:
                raise HTTPException(
                    detail=f"上级菜单不存在(菜单代码: {self.code[:-4]})",
                    status_code=HTTP_400_BAD_REQUEST,
                )

        obj = session.scalar(
            sql.select(Menu).where(Menu.scope == self.scope, Menu.name == self.name)
        )

        if obj and obj.id != self.id:
            raise HTTPException(
                detail="菜单名称已存在",
                status_code=HTTP_400_BAD_REQUEST,
            )

        obj = session.scalar(
            sql.select(Menu).where(Menu.scope == self.scope, Menu.path == self.path)
        )

        if obj and obj.id != self.id:
            raise HTTPException(
                detail="菜单路径已存在",
                status_code=HTTP_400_BAD_REQUEST,
            )

        self.prefix = self.prefix.rstrip("*").rstrip("/")

    def children(self, all: bool = False) -> list[Self]:
        """
        子菜单
        """

        session = self._sa_instance_state.session

        objs = []

        queryset = sql.select(Menu).where(
            Menu.code != self.code, Menu.code.startswith(self.code)
        )

        if not all:
            queryset = queryset.where(func.length(Menu.code) == len(self.code) + 4)

        for obj in session.scalars(queryset.order_by(Menu.code)):
            objs.append(obj)

        return objs

    def enforce(self, auth_user: Any) -> tuple[bool, bool, bool, bool]:
        """
        权限检查
        """

        session = self._sa_instance_state.session

        GET = False
        POST = False
        PUT = False
        DELETE = False

        if self.prefix:
            if auth_user.super_admin:
                GET = True
                POST = True
                PUT = True
                DELETE = True
            else:
                for obj in session.scalars(
                    sql.select(Menu).where(
                        PermissionRule.scope == self.scope,
                        PermissionRule.role.in_(auth_user.get_current_roles()),
                        PermissionRule.menu_id == self.id,
                    )
                ):
                    if obj.GET:
                        GET = True

                    if obj.POST:
                        POST = True

                    if obj.PUT:
                        PUT = True

                    if obj.DELETE:
                        DELETE = True

        return GET, POST, PUT, DELETE


class PermissionRule(Base):
    """
    权限策略
    """

    __tablename__ = "permission_rule"

    id: Mapped[int] = mapped_column(primary_key=True, comment="ID")
    scope: Mapped[str] = mapped_column(String(64), comment="SCOPE")
    role: Mapped[int] = mapped_column(comment="角色")
    path: Mapped[str] = mapped_column(String(128), comment="路径")
    menu_id: Mapped[int] = mapped_column(
        ForeignKey(Menu.id, ondelete="CASCADE"), nullable=True, comment="菜单"
    )

    GET: Mapped[bool] = mapped_column(default=False, comment="GET操作")
    POST: Mapped[bool] = mapped_column(default=False, comment="POST操作")
    PUT: Mapped[bool] = mapped_column(default=False, comment="PUT操作")
    DELETE: Mapped[bool] = mapped_column(default=False, comment="DELETE操作")

    __table_args__ = (UniqueConstraint("scope", "role", "path"),)

    menu: Mapped[Menu] = relationship()

    def validate_data(self, session: Session | None = None) -> None:
        """
        数据校验
        """

        if not self.menu:
            raise HTTPException(
                detail="未知菜单",
                status_code=HTTP_400_BAD_REQUEST,
            )

        if not self.menu.prefix:
            raise HTTPException(
                detail="菜单设置错误",
                status_code=HTTP_400_BAD_REQUEST,
            )

        self.scope = self.menu.scope
        self.path = self.menu.prefix

        obj = session.scalar(
            sql.select(PermissionRule).where(
                PermissionRule.scope == self.scope,
                PermissionRule.role == self.role,
                PermissionRule.path == self.path,
            )
        )

        if obj and obj.id != self.id:
            raise HTTPException(
                detail="权限策略已存在",
                status_code=HTTP_400_BAD_REQUEST,
            )

        with Redis() as conn:
            conn.delete_cache(self.__class__.__name__.lower())

    def policy(self):
        CRUD = []

        for name, value in (
            ("GET", self.GET),
            ("POST", self.POST),
            ("PUT", self.PUT),
            ("DELETE", self.DELETE),
        ):
            if not value:
                continue

            CRUD.append(name)

        data = []

        if CRUD:
            sub = f"{self.scope}:{self.role}"

            if len(CRUD) > 1:
                act = "|".join([f"({x})" for x in CRUD])
            else:
                act = CRUD[0]

            for path in (self.path, self.path + "/*"):
                data.append(", ".join(("p", sub, path, act)))

        return data

    @classmethod
    def enforcer(cls) -> casbin.Enforcer:
        """
        权限检查器
        """

        class Adapter(casbin.persist.Adapter):
            def load_policy(self, model):
                def get_data():
                    data = []

                    with Session(engine) as session, session.begin():
                        for obj in session.scalars(sql.select(PermissionRule)):
                            data += obj.policy()

                    return data

                with Redis() as conn:
                    data = conn.cache(cls.__name__.lower(), get_data, expire=30 * 60)

                    for policy in data:
                        casbin.persist.load_policy_line(policy, model)

        m = casbin.Model()
        m.load_model_from_text(
            """
                [request_definition]
                r = sub, obj, act

                [policy_definition]
                p = sub, obj, act

                [policy_effect]
                e = some(where (p.eft == allow))

                [matchers]
                m = r.sub == p.sub && keyMatch(r.obj, p.obj) && regexMatch(r.act, p.act) || r.sub == "admin"
            """
        )

        return casbin.Enforcer(m, Adapter())

    @classmethod
    def enforce(
        cls, enforcer: casbin.Enforcer, subs: list[str], obj: str, act: str
    ) -> bool:
        """
        权限检查
        """

        for sub in subs:
            if enforcer.enforce(sub, obj, act):
                return True

        return False
