package i18n

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Не переводятся: внутренние сообщения и ответы на вопросы консоли.
var untranslated = map[string]bool{
	"укажи pipe": true, "err запрос неверен": true, "неверный запрос службы": true, "неверные учётные данные": true,
	"укажи профиль и pipe": true, "занято": true, "неверный запрос": true, "enable <профиль> <challengeHex> <secretHex>": true, "д": true, "да": true, "окно закрыто без ввода пароля": true,
}

// Передаются в T через переменную, поэтому в коде литералом не встречаются.
var viaVariable = map[string]bool{
	"обфусцированные скрипты": true, "JS/VBS запускает скачанный exe": true,
	"исполняемое содержимое из почты и вебпочты": true, "кража учётных данных из LSASS": true,
}

func constString(e ast.Expr) (string, bool) {
	switch v := e.(type) {
	case *ast.BasicLit:
		if v.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(v.Value)
		return s, err == nil
	case *ast.BinaryExpr:
		l, ok1 := constString(v.X)
		r, ok2 := constString(v.Y)
		return l + r, ok1 && ok2 && v.Op == token.ADD
	case *ast.ParenExpr:
		return constString(v.X)
	}
	return "", false
}

func cyrillic(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool { return r >= 0x400 && r <= 0x4ff })
}

// Каждая строка, переданная в T или Tf, должна иметь перевод, а в таблице не должно быть строк, которых нет в коде.
func TestCoverage(t *testing.T) {
	used := map[string]string{}
	root := filepath.Join("..", "..")
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return err
		}
		f, err := parser.ParseFile(token.NewFileSet(), p, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(f, func(n ast.Node) bool {
			c, ok := n.(*ast.CallExpr)
			if !ok || len(c.Args) == 0 {
				return true
			}
			sel, ok := c.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			x, ok := sel.X.(*ast.Ident)
			// errors.New("...") на уровне пакета переводится при выводе по тексту ошибки.
			isErr := ok && x.Name == "errors" && sel.Sel.Name == "New"
			if !isErr && (!ok || x.Name != "i18n" || (sel.Sel.Name != "T" && sel.Sel.Name != "Tf")) {
				return true
			}
			if s, ok := constString(c.Args[0]); ok && (!isErr || cyrillic(s)) {
				used[s] = p
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for s, p := range used {
		if _, ok := en[s]; !ok && !untranslated[s] {
			t.Errorf("нет перевода (%s): %q", filepath.Base(p), s)
		}
	}
	for s := range en {
		if _, ok := used[s]; !ok && !viaVariable[s] {
			t.Errorf("перевод не используется: %q", s)
		}
	}
}
