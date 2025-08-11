from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from crud.user_crud import (
    create_user,
    get_user_by_email,
    activate_user,
    reset_request_user_password,
    reset_completion_user_password
)
from database import get_db

from exceptions import BaseSecurityError
from schemas import (
    UserRegistrationResponseSchema,
    UserRegistrationRequestSchema,
    UserActivationRequestSchema,
    MessageResponseSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema
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

    new_user = await create_user(user_data=user_data, db=db)
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
async def password_reset_request(user_data: PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)):
    db_user = await get_user_by_email(email=user_data.email, db=db)

    return await reset_request_user_password(user=db_user, db=db)


@router.post("/reset-password/complete/", status_code=200, response_model=MessageResponseSchema)
async def password_reset_complete(user_data: PasswordResetCompleteRequestSchema, db: AsyncSession = Depends(get_db)):
    db_user = await get_user_by_email(email=user_data.email, db=db)
    if not db_user or not db_user.is_active:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    return await reset_completion_user_password(
        user=db_user,
        new_password=user_data.password,
        token=user_data.token,
        db=db
    )
