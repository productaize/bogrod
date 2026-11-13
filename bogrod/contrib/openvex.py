import json


class OpenVexStatements:
    def __init__(self, path):
        self.path = path
        self.vuln = {}
        self.statements = []

    def read(self):
        with open(self.path, 'rb') as f:
            self.data = json.load(f)
        self.statements = self.data['statements']
        for stmt in self.statements:
            vuln_id = stmt['vulnerability']['name']
            self.vuln[vuln_id] = stmt

    def get_by_vuln(self, vuln_id):
        return self.vuln.get(vuln_id)

    def match_product(self, vuln_id, product_id):
        stmt = self.get_by_vuln(vuln_id) or {}
        match = any(product_id in stmt_prod_id for stmt_prod_id in stmt.get('products', []))
        return match

    def as_cyclonedx_vex(self, vuln_id):
        # OpenVEX status -> CycloneDX analysis state
        STATUS_MAP = {
            "not_affected": "not_affected",
            "affected": "exploitable",
            "fixed": "resolved",
            "under_investigation": "in_triage",
        }

        # OpenVEX justification -> CycloneDX analysis justification
        JUSTIFICATION_MAP = {
            "component_not_present": "requires_dependency",
            "vulnerable_code_not_present": "code_not_present",
            "vulnerable_code_not_in_execute_path": "code_not_reachable",
            "vulnerable_code_cannot_be_controlled_by_adversary": "protected_at_runtime",
            "inline_mitigations_already_exist": "protected_by_mitigating_control",
        }
        stmt = self.get_by_vuln(vuln_id)
        vex = {}
        # -- status => state
        vex['state'] = STATUS_MAP.get(stmt['status'], 'in_triage')
        # -- impact_stmt|status_notes|action_stmt => detail
        detail_parts = []
        if stmt.get("impact_stmt"):
            detail_parts.append(stmt["impact_stmt"])
        if stmt.get("status_notes"):
            detail_parts.append(stmt["status_notes"])
        if vex['state'] == "exploitable" and stmt.get("action_stmt"):
            detail_parts.append(f"Action: {stmt['action_stmt']}")
        if detail_parts:
            vex['detail'] = " ".join(detail_parts)
        # justification => justification
        justification = stmt.get("justification")
        if vex['state'] == "not_affected" and justification:
            vex['justification'] = JUSTIFICATION_MAP.get(justification, 'protected_by_mitigating_control')
        # response
        if vex['state'] == "resolved":
            vex["response"] = ["update"]
        elif vex['state'] == "exploitable":
            vex["response"] = ["can_not_fix"] if not stmt.get("action_statement") else ['update']
        # timestamps
        first_issued = self.data.get("timestamp")
        last_updated = stmt.get("action_statement_timestamp") or stmt.get("last_updated")
        if first_issued:
            vex["firstIssued"] = first_issued
        if last_updated:
            vex["lastUpdated"] = last_updated
        vex['sources'] = [self.path]
        return vex
