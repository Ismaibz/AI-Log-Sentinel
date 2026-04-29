"""Mitigation rule generator — UFW/Nginx deny rules."""

# TODO: MitigationRule dataclass (rule_type, command, description, critical, rollback_command)
# TODO: RuleGenerator class
#   generate(threat: ThreatAssessment) → list[MitigationRule]
#   Mapping: block_ip → UFW + Nginx deny, block_path → Nginx location, rate_limit → Nginx limit_req_zone
