from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from crud.user_crud import create_user, get_user_by_email, activate_user, reset_request_user_password
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from exceptions import BaseSecurityError
from schemas import (
    UserRegistrationResponseSchema,
    UserRegistrationRequestSchema,
    UserActivationRequestSchema,
    MessageResponseSchema,
    UserBaseSchema
)
from security.interfaces import JWTAuthManagerInterface

router = APIRouter()


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=201
)
async def register_user(user_data: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)):
    db_user = await get_user_by_email(email=user_data.email, db=db)
    if db_user:
        raise HTTPException(
            status_code=409,
            detail=f"A user with this email {user_data.email} already exists."
        )

    new_user = await create_user(user=user_data, db=db)
    return new_user


@router.post("/activate/", status_code=200, response_model=MessageResponseSchema)
async def activate_account(activation_data: UserActivationRequestSchema, db: AsyncSession = Depends(get_db)):
    db_user = await get_user_by_email(email=activation_data.email, db=db)
    if not db_user:
        raise HTTPException(
            status_code=409,
            detail=f"A user with this email {activation_data.email} not found."
        )

    return await activate_user(
        user=db_user,
        activation_token=activation_data.token,
        db=db
    )


@router.post("/password-reset/request/", status_code=200, response_model=MessageResponseSchema)
async def password_reset_request(user_data: UserBaseSchema, db: AsyncSession = Depends(get_db)):
    db_user = await get_user_by_email(email=user_data.email, db=db)

    return await reset_request_user_password(user=db_user, db=db)
