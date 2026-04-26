package authz_test

import data.authz
import rego.v1

test_developer_reads_projects if {
	authz.allow with input as {
		"user": {"roles": ["developer"], "trust_score": 0.75},
		"resource": "projects",
		"action": "read",
	}
}

test_low_trust_denied if {
	not authz.allow with input as {
		"user": {"roles": ["developer"], "trust_score": 0.40},
		"resource": "projects",
		"action": "read",
	}
}

test_secrets_requires_high_trust if {
	not authz.allow with input as {
		"user": {"roles": ["developer"], "trust_score": 0.70},
		"resource": "secrets",
		"action": "read",
	}
}

test_secrets_allowed_high_trust if {
	authz.allow with input as {
		"user": {"roles": ["developer"], "trust_score": 0.90},
		"resource": "secrets",
		"action": "read",
	}
}

test_viewer_reads_reports if {
	authz.allow with input as {
		"user": {"roles": ["viewer"], "trust_score": 0.65},
		"resource": "reports",
		"action": "read",
	}
}

test_wrong_role_denied if {
	not authz.allow with input as {
		"user": {"roles": ["viewer"], "trust_score": 0.95},
		"resource": "admin",
		"action": "write",
	}
}
