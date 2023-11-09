from base.models import *


class AdminUser(Base):
    """
    管理员
    """

    __tablename__ = "admin_user"

    ROLE_CHOICES = (
        (1, "系统管理员"),
        (2, "运维人员"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, comment="ID")
    username: Mapped[str] = mapped_column(String(64), unique=True, comment="用户名")
    password: Mapped[PasswordType] = mapped_column(PasswordType(), comment="密码")
    role: Mapped[int] = mapped_column(ChoiceType(ROLE_CHOICES), default=1, comment="角色")
    super_admin: Mapped[bool] = mapped_column(default=False, comment="是否超级用户")
    enable: Mapped[bool] = mapped_column(default=False, comment="启用")

    create_time: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), default=now, comment="创建时间"
    )

    def validate_data(self, session: Session | None = None) -> None:
        """
        数据校验
        """

        obj = session.scalar(
            sql.select(AdminUser).where(AdminUser.username == self.username)
        )

        if obj and obj.id != self.id:
            raise HTTPException(
                detail="用户名已存在",
                status_code=HTTP_400_BAD_REQUEST,
            )

    def get_current_roles(self) -> list[int]:
        """
        当前角色
        """

        return [self.role.code]
