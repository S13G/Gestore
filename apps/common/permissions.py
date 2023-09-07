from rest_framework.permissions import BasePermission


class IsAuthenticatedTenant(BasePermission):

    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated and request.user.tenant_profile)


class IsAuthenticatedLandLord(BasePermission):

    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated and request.user.landlord_profile)
