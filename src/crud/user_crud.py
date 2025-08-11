from datetime import datetime
from typing import cast

from fastapi import HTTPException
from pydantic import EmailStr
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from database import UserModel, UserGroupModel, UserGroupEnum, ActivationTokenModel, PasswordResetTokenModel
from schemas import UserRegistrationRequestSchema
from security.passwords import hash_password


async def create_user(user: UserRegistrationRequestSchema, db: AsyncSession):
    try:
        result = await db.execute(
            select(UserGroupModel.id)
            .where(UserGroupModel.name == UserGroupEnum.USER)
        )
        default_group_id = result.scalar_one_or_none()

        hashed = hash_password(user.password)
        db_user = UserModel(
            email=cast(str, user.email),
            _hashed_password=hashed,
            group_id=default_group_id,
        )
        db.add(db_user)
        await db.flush()

        activation_token = ActivationTokenModel(user_id=db_user.id)
        db.add(activation_token)
        await db.commit()

        return db_user

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred during user creation.")


async def get_user_by_email(email: EmailStr, db: AsyncSession):
    result = await db.execute(
        select(UserModel)
        .options(
            joinedload(UserModel.activation_token),
            joinedload(UserModel.password_reset_token)
        )
        .where(UserModel.email == email)
    )
    return result.unique().scalar_one_or_none()


async def activate_user(user: UserModel, activation_token: str, db: AsyncSession) -> dict:
    if user.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")

    user_token_model = user.activation_token
    if not user_token_model or user_token_model.expires_at < datetime.now():
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")
    if user_token_model.token != activation_token:
        raise HTTPException(status_code=401)

    user.is_active = True
    await db.delete(user_token_model)
    await db.commit()
    return {"message": "User account activated successfully."}


async def reset_request_user_password(user: UserModel, db: AsyncSession):
    if user and user.is_active:

        if user.password_reset_token:
            await db.delete(user.password_reset_token)
            await db.flush()

        password_reset_token = PasswordResetTokenModel(user_id=user.id)
        db.add(password_reset_token)
        await db.commit()

    return {"message": "If you are registered, you will receive an email with instructions."}


async def reset_completion_user_password(user: UserModel, new_password: str, token: str, db: AsyncSession):
    user_token_model = user.password_reset_token
    if not user_token_model:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    if user_token_model.expires_at < datetime.now() or user_token_model.token != token:
        await db.delete(user_token_model)
        await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    hashed = hash_password(new_password)
    user._hashed_password = hashed

    try:
        await db.delete(user_token_model)
        await db.commit()

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while resetting the password.")

    return {"message": "Password reset successfully."}
