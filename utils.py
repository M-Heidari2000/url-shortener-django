from ipware import get_client_ip

def generate_log(request, status_code=''):
    method = request.method
    ip, _ = get_client_ip(request)
    os = request.user_agent.os.family
    end_point = request.build_absolute_uri()
    browser = request.user_agent.browser.family

    log_info = {
        'url': end_point,
        'request_method': method,
        'user_ip': ip,
        'operating_system': os,
        'browser': browser,
        'status_code': status_code,
    }
    return log_info

