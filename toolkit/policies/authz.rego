package authz

import rego.v1

default allow := false

# Regular resources: role + minimum trust
allow if {
	input.user.roles[_] == required_role[input.resource]
	input.user.trust_score >= 0.60
}

# Sensitive resources: role + high trust
allow if {
	sensitive_resources[input.resource]
	input.user.roles[_] == required_role[input.resource]
	input.user.trust_score >= 0.85
}

sensitive_resources := {"secrets", "admin", "audit"}

required_role := {
	"projects": "developer",
	"reports":  "viewer",
	"secrets":  "developer",
	"admin":    "admin",
	"audit":    "security_admin",
}
