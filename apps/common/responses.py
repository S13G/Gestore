from rest_framework.response import Response


class CustomResponse:
    ALL_SUCCESS_CODES = {
        200: {"code": 0, "message": "Fetched successfully"},
        201: {"code": 0, "message": "Created successfully"},
        202: {"code": 0, "message": "Updated successfully"},
        204: {"code": 0, "message": "Deleted successfully"},
    }

    ALL_ERROR_CODES = {
        404: {"code": 1, "message": "Resource not found"},
        400: {"code": 2, "message": "Bad request"},
        401: {"code": 4, "message": "Authorization credentials not provided"},
        403: {"code": 5, "message": "Access denied"},
        500: {"code": 6, "message": "Something went wrong"},
        409: {"code": 3, "message": "Already exists"},
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
