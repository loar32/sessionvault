package audit

import "testing"

func TestPolicyQuery(t *testing.T) {
	if err := procAuditQuery.Find(); err != nil {
		t.Fatal(err)
	}
	if _, err := fileSystemPolicy(); err != nil {
		t.Skip("запрос политики требует прав администратора:", err)
	}
}
