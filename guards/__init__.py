"""Operator safety guards: untrusted-input wrapping, output gating, tool tiering."""

from .wrap_untrusted import (
    CAPS,
    WrapResult,
    set_jailbreak_file,
    wrap_chat_message,
    wrap_email,
    wrap_record_field,
    wrap_untrusted,
    wrap_vendor_content,
    wrap_web_content,
)
from .output_gate import (
    MODE_ENFORCE,
    MODE_LOG_ONLY,
    OutputGateResult,
    check_message,
    check_record_write,
    get_current_mode,
    reload_allowlist,
    set_allowlist_file,
)
from .capability_gate import check_tool_call, is_write_tool, resolve_tier

__version__ = "0.1.0"
__all__ = [
    "CAPS", "WrapResult", "set_jailbreak_file", "wrap_chat_message", "wrap_email",
    "wrap_record_field", "wrap_untrusted", "wrap_vendor_content", "wrap_web_content",
    "MODE_ENFORCE", "MODE_LOG_ONLY", "OutputGateResult", "check_message",
    "check_record_write", "get_current_mode", "reload_allowlist", "set_allowlist_file",
    "check_tool_call", "is_write_tool", "resolve_tier",
]
