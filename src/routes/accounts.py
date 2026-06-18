from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from exceptions import BaseSecurityError, TokenExpiredError
from schemas import (
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    TokenRefreshResponseSchema,
    UserLoginResponseSchema,
    UserLoginRequestSchema,
    TokenRefreshRequestSchema,
    UserRegistrationRequestSchema,
)
from security.interfaces import JWTAuthManagerInterface


SUCCESS_RESPONSE = {
    "message": (
        "If you are registered, "
        "you will receive an email with instructions."
    )
}


router = APIRouter()


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
    responses={
        201: {
            "description": "User registered successfully.",
        },
        500: {
            "description": "Error during registration.",
            "content": {
                "application/json": {
                    "example": {"detail": "An error occurred during user creation."}
                }
            },
        }
    },
)
async def register_user(
    user_data: UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    existing_check = select(UserModel).where(UserModel.email == user_data.email)
    existing_result = await db.execute(existing_check)
    existing_user = existing_result.scalars().first()

    if existing_user:
        raise HTTPException(
            status_code=409,
            detail=f"A user with this email {user_data.email} already exists.",
        )
    try:
        group = await db.scalar(
            select(UserGroupModel)
            .where(UserGroupModel.name == UserGroupEnum.USER)
        )
        user = UserModel.create(
            email=user_data.email,
            raw_password=user_data.password,
            group_id=group.id,
        )
        db.add(user)
        await db.flush()

        activation_token = ActivationTokenModel(user_id=user.id)
        db.add(activation_token)

        await db.commit()
        await db.refresh(user, ["group"])

        return UserRegistrationResponseSchema.model_validate(user)
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500, detail="An error occurred during user creation."
        )


@router.post(
    "/activate/",
    responses={
        200: {
            "description": "User account activated successfully.",
            "content": {
                "application/json": {
                    "example": {"detail": "User updated successfully."}
                }
            },
        },
        400: {
            "description": "Error during user activation.",
            "content": {
                "application/json": {
                    "example": {"detail": "Invalid or expired activation token."}
                }
            }
        }
    },
    status_code=status.HTTP_200_OK,
)
async def activate_user(
    activation_data: UserActivationRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    db_user = await db.scalar(
        select(UserModel)
        .where(UserModel.email == activation_data.email)
    )

    if db_user is None:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired activation token."
        )

    if db_user.is_active:
        raise HTTPException(
            status_code=400,
            detail="User account is already active."
        )

    token = await db.scalar(
        select(ActivationTokenModel)
        .where(ActivationTokenModel.user_id == db_user.id)
    )

    if token is None:
        raise HTTPException(
            status_code=400, detail="Invalid or expired activation token."
        )

    expires_at = cast(datetime, token.expires_at).replace(tzinfo=timezone.utc)

    if (
        token.token != activation_data.token
        or expires_at < datetime.now(timezone.utc)
    ):
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired activation token."
        )

    db_user.is_active = True

    await db.delete(token)
    await db.commit()

    return {"message": "User account activated successfully."}


@router.post(
    "/password-reset/request/",
    status_code=status.HTTP_200_OK,
    responses={
        200: {
            "description": "User password reset request successfully."
        }
    },
)
async def password_reset(
    data: PasswordResetRequestSchema,
    db: AsyncSession = Depends(get_db)
):
    db_user = await db.scalar(
        select(UserModel).where(UserModel.email == data.email)
    )

    if db_user is None or not db_user.is_active:
        return SUCCESS_RESPONSE

    await db.execute(
        delete(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == db_user.id
        )
    )

    reset_token = PasswordResetTokenModel(user_id=cast(int, db_user.id))
    db.add(reset_token)
    await db.commit()
    await db.refresh(reset_token)

    return SUCCESS_RESPONSE


@router.post(
    "/reset-password/complete/",
    status_code=status.HTTP_200_OK,
)
async def password_reset_complete(
    data: PasswordResetCompleteRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    db_user = await db.scalar(
        select(UserModel).where(UserModel.email == data.email)
    )
    if db_user is None or not db_user.is_active:
        raise HTTPException(
            status_code=400,
            detail="Invalid email or token."
        )

    db_token = await db.scalar(
        select(PasswordResetTokenModel)
        .where(PasswordResetTokenModel.token == data.token)
    )

    if db_token is None:
        user_token = await db.scalar(
            select(PasswordResetTokenModel).
            where(PasswordResetTokenModel.user_id == db_user.id)
        )
        if user_token is not None:
            await db.delete(user_token)
        await db.commit()
        raise HTTPException(
            status_code=400,
            detail="Invalid email or token."
        )

    expires_at = cast(datetime, db_token.expires_at).replace(tzinfo=timezone.utc)

    if (
        db_token.user_id != db_user.id
        or expires_at < datetime.now(timezone.utc)
    ):
        await db.delete(db_token)
        await db.commit()
        raise HTTPException(
            status_code=400,
            detail="Invalid email or token."
        )

    try:
        db_user.password = data.password
        await db.commit()
        await db.refresh(db_user)

        return {
            "message": "Password reset successfully."
        }

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred while resetting the password."
        )


@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def login(
    credentials: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings),
):
    db_user = await db.scalar(
        select(UserModel).where(UserModel.email == credentials.email)
    )
    if not db_user or not db_user.verify_password(credentials.password):
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password."
        )
    if not db_user.is_active:
        raise HTTPException(
            status_code=403,
            detail="User account is not activated."
        )

    try:
        access_token = jwt_manager.create_access_token({"user_id": db_user.id})
        refresh_token = jwt_manager.create_refresh_token({"user_id": db_user.id})
        token = RefreshTokenModel.create(
            token=refresh_token,
            user_id=db_user.id,
            days_valid=settings.LOGIN_TIME_DAYS
        )
        db.add(token)
        await db.commit()
        await db.refresh(token)
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
        }
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred while processing the request."
        )


@router.post(
    "/refresh/",
    response_model=TokenRefreshResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def refresh(
    ref_token: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    try:
        token = jwt_manager.decode_refresh_token(ref_token.refresh_token)
    except TokenExpiredError:
        raise HTTPException(
            status_code=400,
            detail="Token has expired."
        )

    db_token = await db.scalar(
        select(RefreshTokenModel)
        .where(RefreshTokenModel.token == ref_token.refresh_token)
    )
    if not db_token:
        raise HTTPException(
            status_code=401,
            detail="Refresh token not found."
        )

    user_id = token["user_id"]

    if db_token.user_id != token["user_id"]:
        raise HTTPException(status_code=401, detail="Refresh token not found.")

    user = await db.scalar(select(UserModel).where(UserModel.id == user_id))

    if user is None:
        raise HTTPException(status_code=404, detail="User not found.")

    access_token = jwt_manager.create_access_token({"user_id": user.id})

    return {"access_token": access_token}
