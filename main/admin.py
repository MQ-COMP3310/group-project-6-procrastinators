from django.contrib import admin
from .models import AuditLog


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'event_type', 'user', 'outcome',
                    'affected_object_type', 'source_ip')
    list_filter = ('event_type', 'outcome', 'timestamp')
    search_fields = ('user__username', 'source_ip', 'action_details')
    readonly_fields = ('timestamp', 'event_type', 'user', 'outcome',
                       'affected_object_id', 'affected_object_type',
                       'source_ip', 'action_details')
    ordering = ('-timestamp',)

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def get_queryset(self, request):
        if not request.user.is_staff:
            return AuditLog.objects.none()
        return super().get_queryset(request)
