from .models import AuditLog
import logging
import re

logger = logging.getLogger(__name__)


def log_security_event(event_type, user=None, outcome='SUCCESS',
                       affected_object_id=None, affected_object_type='',
                       source_ip=None, action_details=''):
    try:
        if event_type not in dict(AuditLog.EVENT_CHOICES):
            event_type = 'ADMIN_ACTION'

        if outcome not in ['SUCCESS', 'FAILURE']:
            outcome = 'FAILURE'

        action_details = sanitize_log_details(action_details)

        log = AuditLog.objects.create(
            event_type=event_type,
            user=user,
            outcome=outcome,
            affected_object_id=affected_object_id,
            affected_object_type=affected_object_type,
            source_ip=source_ip,
            action_details=action_details
        )
        return log

    except Exception as e:
        logger.error(f'Audit logging failed: {str(e)}')
        return None


def sanitize_log_details(details):
    if not isinstance(details, str):
        details = str(details)

    sensitive_keywords = [
        'password', 'hash', 'token', 'cookie', 'secret',
        'api_key', 'csrf', 'session', 'auth'
    ]

    for keyword in sensitive_keywords:
        pattern = re.compile(
            rf'\w*{re.escape(keyword)}\w*\s*:\s*\S+',
            re.IGNORECASE
        )
        details = pattern.sub(f'{keyword}: [REDACTED]', details)

    return details


def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR')

    return ip
