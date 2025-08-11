from typing import cast

from fastapi import HTTPException
from pydantic import EmailStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from database import UserModel, UserGroupModel, UserGroupEnum, ActivationTokenModel
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

    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred during user creation.")


async def get_user_by_email(email: EmailStr, db: AsyncSession):
    result = await db.execute(
        select(UserModel)
        .options(
            joinedload(UserModel.activation_token),
        )
        .where(UserModel.email == email)
    )
    return result.unique().scalar_one_or_none()


async def activate_user(user: UserModel, activation_token: str, db: AsyncSession) -> dict:
    user_token_model = user.activation_token
    if user_token_model.token != activation_token:
        raise HTTPException(status_code=401)

    user.is_active = True
    await db.delete(user_token_model)
    await db.commit()
    return {"message": "User account activated successfully."}
