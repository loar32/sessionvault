// standin — заглушка вместо Telegram для тестов: просто живёт, чтобы access-check было к чему тянуться.
package main

import "time"

func main() {
	time.Sleep(30 * time.Minute)
}
