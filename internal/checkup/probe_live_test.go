package checkup

import "testing"

// Живая проверка на этом компьютере: поле Known может быть пустым без прав администратора, но разбор не должен падать.
func TestLiveProbe(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	p := winSystem{}.probe()
	t.Logf("%+v", p)
}
