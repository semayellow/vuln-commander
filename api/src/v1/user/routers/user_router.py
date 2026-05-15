import uuid

from fastapi import APIRouter, Depends, status

from api.src.v1.auth.dependencies.auth_dependencies import user_capabilities, admin_capabilities

from api.src.v1.user.dependencies.user_dependencies import get_user_service
from api.src.v1.user.services.user_service import UserService
from shared.schemas.user import UserResponseSchema, UserSchema, UserUpdateSchema

router = APIRouter(prefix="/user")


@router.post(
    "/",
    response_model=UserResponseSchema,
    dependencies=[Depends(admin_capabilities)]
)
async def create_user_handler(
    request: UserSchema,
    user_service: UserService = Depends(get_user_service)
):
    return await user_service.create_user(request)


@router.get(
    "/{user_id}",
    response_model=UserResponseSchema,
    dependencies=[Depends(user_capabilities)]
)
async def get_user_handler(
    user_id: uuid.UUID,
    user_service: UserService = Depends(get_user_service)
):
    return await user_service.get_user(str(user_id))


@router.put(
    "/{user_id}",
    response_model=UserResponseSchema,
    dependencies=[Depends(user_capabilities)]
)
async def update_user_handler(
    user_id: uuid.UUID,
    request: UserUpdateSchema,
    user_service: UserService = Depends(get_user_service)
):
    return await user_service.update_user(str(user_id), request)


@router.delete(
    "/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(admin_capabilities)]
)
async def delete_user_handler(
    user_id: uuid.UUID,
    user_service: UserService = Depends(get_user_service)
):
    await user_service.delete_user(str(user_id))


