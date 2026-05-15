from sqlalchemy.orm import DeclarativeBase

import datetime
from typing import Annotated
from uuid import UUID

from sqlalchemy import DateTime, text
from sqlalchemy.orm import mapped_column

created_at = Annotated[datetime.datetime, mapped_column(server_default=text("TIMEZONE('utc', now())"))]
updated_at = Annotated[datetime.datetime, mapped_column(server_default=text("TIMEZONE('utc', now())"))]
gen_uuid = Annotated[UUID, mapped_column(server_default=text("gen_random_uuid()"), primary_key=True)]
datetime_column = Annotated[datetime.datetime, mapped_column(DateTime)]


class Base(DeclarativeBase):

    def set_not_empty_attrs(self, **kwargs) -> None:
        for attr_name, attr_value in kwargs.items():
            if attr_value:
                setattr(self, attr_name, attr_value)
