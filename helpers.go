package pager

import "log"

func handleFatalError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
