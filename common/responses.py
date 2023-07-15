from rest_framework.exceptions import APIException


class CustomResponse(APIException):
    ALL_SUCCESS_CODES = {
        200: "Fetched successfully",
        201: "Added successfully",
        202: "Updated successfully",
        204: "Deleted successfully",
    }

    ALL_ERROR_CODES = {
        404: "Resource not found",
        400: "Validation error",
        401: "Invalid Access",
        403: "Access denied",
        500: "Something went wrong",
    }

    def __init__(self, code: int, detail: str = None, data: dict = None):
        self.code = code
        self.detail = detail or self.ALL_ERROR_CODES.get(code)
        self.data = data or {}

    def get_full_details(self):
        return {
            "message": self.detail,
            "code": self.code,
            "data": self.data,
            "status": "success" if self.code in self.ALL_SUCCESS_CODES else "failed",
        }
