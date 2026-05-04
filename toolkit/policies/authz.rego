package authz

import rego.v1

default allow := false

# Regular resources: role + minimum trust
allow if {
	not sensitive_resources[input.resource]
	input.user.roles[_] == required_role[input.resource]
	input.user.trust_score >= 0.60
}

# Sensitive resources: role + high trust
allow if {
	sensitive_resources[input.resource]
	input.user.roles[_] == required_role[input.resource]
	input.user.trust_score >= 0.85
}

# deny_reason is set when allow == false, so the caller knows WHY without a second request.
# "insufficient_trust" — user has the right role but trust score is too low → step-up.
# "insufficient_role"  — user lacks the required role → permanent 403.
default deny_reason := "insufficient_role"

deny_reason := "insufficient_trust" if {
	not allow
	has_required_role
}

# Helper: user has the role required for this resource.
has_required_role if {
	required_role[input.resource] == input.user.roles[_]
}

# sensitive_resources require trust_score >= 0.85 (high-risk operations)
sensitive_resources := {"secrets", "admin"}

required_role := {
	"projects": "developer",
	"reports":  "viewer",
	"secrets":  "developer",
	"admin":    "admin",
	"audit":    "security_admin",
}
