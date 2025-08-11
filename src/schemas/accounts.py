from pydantic import BaseModel, EmailStr, field_validator

from database import accounts_validators


class UserBaseSchema(BaseModel):
    email: EmailStr

    @field_validator("email", mode="before")
    @classmethod
    def validate_email(cls, value: str) -> str:
        return accounts_validators.validate_email(user_email=value)


class UserRegistrationRequestSchema(UserBaseSchema):
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        return accounts_validators.validate_password_strength(password=value)


class UserRegistrationResponseSchema(UserBaseSchema):
    id: int

    class Config:
        from_attributes = True
