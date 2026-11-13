import json
import re
from dataclasses import dataclass


@dataclass
class ToolCall:
    name: str
    arguments: dict


TOOL_CALL_RE = re.compile(
    r"",
    re.DOTALL,
)

FUNCTION_RE = re.compile(
    r"<function=(?P<name>[^>]+)>(?P<body>.*?)</function>",
    re.DOTALL,
)

PARAMETER_RE = re.compile(
    r"<parameter=(?P<name>[^>]+)>(?P<value>.*?)</parameter>",
    re.DOTALL,
)


def parse_qwen_tool_calls(text: str) -> list[ToolCall]:
    """Parse Qwen3-Coder XML tool calls from model output."""
    calls: list[ToolCall] = []

    for outer in TOOL_CALL_RE.finditer(text):
        body = outer.group("body")

        for fn in FUNCTION_RE.finditer(body):
            name = fn.group("name").strip()
            args: dict = {}

            for param in PARAMETER_RE.finditer(fn.group("body")):
                key = param.group("name").strip()
                raw_value = param.group("value").strip()

                # Qwen-Coder emits parameter values as text.
                # Try JSON first, useful for arrays/objects/numbers/booleans.
                try:
                    value = json.loads(raw_value)
                except json.JSONDecodeError:
                    value = raw_value

                args[key] = value

            calls.append(ToolCall(name=name, arguments=args))

    return calls


def to_openai_tool_calls(calls: list[ToolCall]) -> list[dict]:
    """Convert parsed calls into an OpenAI-compatible tool_calls structure."""
    return [
        {
            "id": f"call_{i}",
            "type": "function",
            "function": {
                "name": call.name,
                "arguments": json.dumps(call.arguments),
            },
        }
        for i, call in enumerate(calls)
    ]


def maybe_tool_calls(text: str) -> list[dict]:
    try:
        tool_calls = to_openai_tool_calls(parse_qwen_tool_calls(text))
    except:
        tool_calls = []
    return tool_calls
