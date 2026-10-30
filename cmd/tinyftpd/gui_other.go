//go:build !windows

package main

import "errors"

func runGUI(string) error { return errors.New("the GUI is only available on Windows") }
