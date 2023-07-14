from rest_framework.response import Response


class CustomResponse:
    ALL_SUCCESS_CODES = {
        200: "Fetched successfully",
        201: "Added successfully",
        202: "Updated successfully",
        204: "Deleted successfully",
    }

    ALL_ERROR_CODES = {
        404: "Resource not found",
        400: "Validation error",
        401: "Invalid Access Token",
        403: "Access denied",
        500: "Something went wrong",
    }

    def __init__(self, code: int, data: dict = None, message: str = None):
        self.code = code
        self.data = data or {}
        self.message = message

    @property
    def status(self):
        return "success" if self.code in self.ALL_SUCCESS_CODES else "failed"

    def get_message(self):
        if self.message is None:
            if self.code in self.ALL_SUCCESS_CODES:
                self.message = self.ALL_SUCCESS_CODES[self.code]
            elif self.code in self.ALL_ERROR_CODES:
                self.message = self.ALL_ERROR_CODES[self.code]
        return self.message

    def to_response(self):
        return Response(
                {
                    "code": self.code,
                    "data": self.data,
                    "message": self.get_message(),
                    "status": self.status,
                },
                status=self.code,
        )
