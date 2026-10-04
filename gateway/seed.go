package main

import (
	"context"
	"fmt"
	"golang.org/x/crypto/bcrypt"
)

var tenants = []string{"acme", "orbit"}

func seed(s Store, password string) error {
	hash, e := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if e != nil {
		return e
	}
	for _, tenant := range tenants {
		e = s.Tenant(context.Background(), tenant, func(tx Tx) error {
			put := func(table, id string, r Record) error {
				if _, e := tx.Get(table, id); e == nil {
					return nil
				} else if e != errMissing {
					return e
				}
				return tx.Insert(table, id, r)
			}
			for _, role := range []string{"analyst", "approver"} {
				if e := put("users", role, Record{"username": role, "role": role, "password_hash": string(hash)}); e != nil {
					return e
				}
			}
			permissions := Record{"siem.search": "allow", "identity.read": "allow", "asset.lookup": "allow", "threat.lookup": "allow", "guidance.read": "allow", "identity.disable": "approval", "identity.delete": "deny"}
			if e := put("policies", "v1", Record{"version": "v1", "permissions": permissions}); e != nil {
				return e
			}
			if e := put("agents", "incident-response", Record{"policy_version": "v1", "active": true}); e != nil {
				return e
			}
			if e := put("identities", "employee-438", Record{"display_name": "Employee 438", "disabled": false, "asset_id": "asset-17"}); e != nil {
				return e
			}
			if e := put("assets", "asset-17", Record{"name": "Engineering workstation", "classification": "internal", "owner": "engineering"}); e != nil {
				return e
			}
			for i := 1; i <= 6; i++ {
				if e := put("events", fmt.Sprintf("EVT-%s-%03d", tenant, i), Record{"identity_id": "employee-438", "timestamp": fmt.Sprintf("2026-10-01T09:%02d:00Z", i), "event": "failed_login", "source": "TEST-NET-3", "indicator": "indicator-7", "severity": "high"}); e != nil {
					return e
				}
			}
			if e := put("events", "EVT-"+tenant+"-007", Record{"identity_id": "employee-438", "timestamp": "2026-10-01T09:08:00Z", "event": "successful_login", "source": "TEST-NET-3", "indicator": "indicator-7", "severity": "high"}); e != nil {
				return e
			}
			if e := put("threat_intel", "indicator-7", Record{"risk": "high", "description": "Synthetic indicator associated with credential abuse", "source_ref": "TI-007"}); e != nil {
				return e
			}
			return put("guidance", "SEC-IR-01", Record{"text": "Six failed logins followed by a success from a high-risk indicator warrant investigation. Containment requires independent human approval.", "section": "4.3"})
		})
		if e != nil {
			return e
		}
	}
	return nil
}
