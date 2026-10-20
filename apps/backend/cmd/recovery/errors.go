package main

import "errors"

// errNoCommand is returned when the arguments name no command.
var errNoCommand = errors.New("name a command: list or approve XID")

// errApproveArgs is returned when approve does not get exactly one request XID.
var errApproveArgs = errors.New("approve needs the XID of one request")
