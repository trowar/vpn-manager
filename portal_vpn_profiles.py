def default_profile_mode_from_policy() -> str:
    return "global"


def detect_client_platform(user_agent: str) -> str:
    ua = (user_agent or "").lower()
    if "android" in ua:
        return "android"
    if any(token in ua for token in ("iphone", "ipad", "ipod", "ios")):
        return "ios"
    if "macintosh" in ua or "mac os x" in ua:
        return "macos"
    if "windows" in ua:
        return "windows"
    if "linux" in ua:
        return "linux"
    return "official"


def detect_openvpn_platform(user_agent: str) -> str:
    return detect_client_platform(user_agent)
