from rest_framework.response import Response


class CustomResponse:
    ALL_SUCCESS_CODES = {
        200: "Fetched successfully",
        201: "Created successfully",
        202: "Updated successfully",
        204: "Deleted successfully",
    }

    ALL_ERROR_CODES = {
        404: "Resource not found",
        400: "Validation error",
        401: "Authorization credentials not provided",
        403: "Access denied",
        500: "Something went wrong",
        409: "Already exists"
    }

    @classmethod
    def generate_response(cls, code: int, data: dict = None, msg=None):
        if code in cls.ALL_SUCCESS_CODES:
            status = "success"
            msg = cls.ALL_SUCCESS_CODES[code] if msg is None else msg
        else:
            status = "error"
            if code in cls.ALL_ERROR_CODES:
                msg = cls.ALL_ERROR_CODES[code] if msg is None else msg

        return Response(
            {"status_code": code, "data": data or {}, "msg": msg, "status": status}, status=code
        )
