import json
import logging
from pathlib import Path

import httpx
import json_repair
from openai import OpenAI
from tqdm import tqdm

from bogrod.analysis import prompts
from bogrod.analysis.tools import maybe_tool_calls

logger = logging.getLogger(__name__)


def web_search(query: str) -> str:
    """Search the web using Exa API"""
    import keyring

    EXA_API_KEY = keyring.get_password('exa', 'apikey')
    response = httpx.post(
        "https://api.exa.ai/search", json={"query": query, "numResults": 3}, headers={"x-api-key": EXA_API_KEY}
    )
    results = response.json().get("results", [])
    return "\n".join([f"{r['title']}: {r['url']}" for r in results])


def web_fetch(url: str) -> str:
    """Fetch content from a URL using Exa API"""
    response = httpx.post("https://api.exa.ai/contents", json={"urls": [url]}, headers={"x-api-key": EXA_API_KEY})
    results = response.json()['results']
    return results[0].get('text', '') if results else '-no results-'


def get_cve_description(vuln_id: str) -> str:
    # see https://google.github.io/osv.dev/get-v1-vulns/
    response = httpx.get(f'https://api.osv.dev/v1/vulns/{vuln_id}')
    result = response.json()
    return result.get('details') or result.get('message') or '-no results-'


class LLMCheck:
    def __init__(self, base_url: str, model: str, instructions: str = None, template: str = None):
        self.client = OpenAI(base_url=base_url, api_key="sk-dummy")
        self.model = model
        self.instructions = instructions or prompts.instructions
        self.template = template or 'Consider this deployment: {prompt} and check {vulnerability}: {description}'

    def check(self, vuln_id: str, description=None, deployment_description=None):
        """Check vulnerability against system instructions"""
        tools = [
            {
                "type": "function",
                "function": {
                    "name": "web_search",
                    "description": "Search for vulnerability information",
                    "parameters": {
                        "type": "object",
                        "properties": {"query": {"type": "string"}},
                        "required": ["query"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "web_fetch",
                    "description": "Fetch detailed content from a URL",
                    "parameters": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]},
                },
            },
        ]

        tools = [
            {
                "type": "function",
                "function": {
                    "name": "get_cve_description",
                    "description": "retrieve vulnerability information for a given vulnerability id",
                    "parameters": {
                        "type": "object",
                        "properties": {"vuln_id": {"type": "string"}},
                        "required": ["vuln_id"],
                    },
                },
            },
        ]

        description = get_cve_description(vuln_id)

        messages = [
            {"role": "developer", "content": self.instructions},
            {
                "role": "user",
                "content": self.template.format(
                    prompt=deployment_description,
                    vulnerability=description,
                    description=description,
                ),
            },
        ]

        while True:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                tools=tools,
            )

            message = response.choices[0].message if len(response.choices) else ''
            tool_calls = message.tool_calls or maybe_tool_calls(message.content)
            if tool_calls:
                logger.debug(f'calling tools {tool_calls}')
                for call in tool_calls:
                    if call.function.name == "web_search":
                        result = web_search(json.loads(call.function.arguments)["query"])
                    if call.function.name == "web_fetch":
                        result = web_fetch(json.loads(call.function.arguments)["url"])
                    if call.function.name == 'get_cve_description':
                        result = get_cve_description(json.loads(call.function.arguments)["vuln_id"])
                    logger.debug(f'   => {str(result)[:50]}')

                    messages.append(message.to_dict())
                    messages.append({
                        "role": "tool",
                        "content": result,
                        "tool_call_id": call.id,
                    })
            else:
                break

        # Parse response into structured format
        content = response.choices[0].message.content
        logger.debug(f'final response {content}')
        if 'json:' in content:
            data = content.split('json:', 1)[1]
        else:
            data = content
        return json_repair.loads(data) if data else {}


def run_checks(checker, deployment_description, vulns, target_dir=None):
    """run checks against a set vulnerabilities

    Args:
        checker (LLMCheck):
        deployment_description (str):
        vulns (list[dict]): list of vulnerabilities, from SBOM
        target_dir:

    Returns:
        None
    """
    target_dir = Path(target_dir or 'checks')
    target_dir.mkdir(parents=True, exist_ok=True)

    pbar = tqdm(vulns)
    for vuln in pbar:
        vuln_id = vuln['id']
        pbar.set_description(f'checking {vuln_id}')
        target_file = target_dir / f'check_{vuln_id}.json'
        if target_file.exists():
            with open(target_file, 'r') as fout:
                result = json.load(fout)
            if (
                'error' not in result
                and result.get('justification') not in (None, 'code_not_present')
                and result.get('rationale') is not None
                and result.get('state') not in (None, 'in_triage')
            ):
                # skip checks already done successfully
                logger.info(f'skipping {vuln_id} because {target_file} already exists with a completed state')
                continue
        try:
            result = checker.check(
                vuln_id,
                description=vuln.get('description'),
                deployment_description=deployment_description,
            )
            verdict = result.get('state')
            logger.error(f' => {vuln_id} {verdict} {target_file}')
        except Exception as e:
            logger.error(f'ERROR {e}')
            result = {'error': str(e), 'result': str(result)}
        with open(target_file, 'w') as fout:
            json.dump(result, fout)
