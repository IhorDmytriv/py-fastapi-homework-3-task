from pydantic import BaseModel, EmailStr, field_validator

from database import accounts_validators


class UserBaseSchema(BaseModel):
    email: EmailStr


class UserRegistrationRequestSchema(UserBaseSchema):
    password: str


class UserRegistrationResponseSchema(UserBaseSchema):
    id: int

    class Config:
        from_attributes = True
