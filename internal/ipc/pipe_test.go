package ipc

import (
	"testing"
	"time"
)

func TestPipeRoundTrip(t *testing.T) {
	const name = `\\.\pipe\SessionVaultTest`
	l, err := Listen(name, "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept(0)
			if err != nil {
				return
			}
			line, err := c.ReadLine(2*time.Second, MaxLine)
			if err == nil {
				_ = c.WriteLine("echo:" + line)
			}
			c.Close()
		}
	}()
	time.Sleep(200 * time.Millisecond)
	got, err := Call(name, "status", 3*time.Second)
	if err != nil || got != "echo:status" {
		t.Fatalf("получили %q, %v", got, err)
	}
	got, err = Call(name, "run telegram", 3*time.Second)
	if err != nil || got != "echo:run telegram" {
		t.Fatalf("второй вызов: %q, %v", got, err)
	}
}

func TestAcceptTimeout(t *testing.T) {
	l, err := Listen(`\\.\pipe\SessionVaultTest2`, "D:P(A;;GA;;;SY)(A;;GA;;;BA)")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if _, err := l.Accept(300 * time.Millisecond); err != ErrTimeout {
		t.Fatalf("ждали ErrTimeout, получили %v", err)
	}
}

func TestLongLineRejected(t *testing.T) {
	const name = `\\.\pipe\SessionVaultTest3`
	l, err := Listen(name, "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	res := make(chan error, 1)
	go func() {
		c, err := l.Accept(0)
		if err != nil {
			res <- err
			return
		}
		defer c.Close()
		_, err = c.ReadLine(2*time.Second, MaxLine)
		res <- err
	}()
	time.Sleep(200 * time.Millisecond)
	c, err := Dial(name, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	long := make([]byte, 300)
	for i := range long {
		long[i] = 'A'
	}
	_ = c.WriteLine(string(long))
	if err := <-res; err == nil {
		t.Fatal("длинная строка принята")
	}
}
