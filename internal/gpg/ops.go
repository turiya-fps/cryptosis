package gpg

// VersionCommand prints gpg's version banner.
func VersionCommand() Command {
	return Command{label: "Show gpg version", options: []string{"--version"}}
}

// DumpOptionsCommand lists every option this gpg build understands.
func DumpOptionsCommand() Command {
	return Command{label: "List supported gpg options", options: []string{"--dump-options"}}
}

// ListKeysCommand lists public keys, or secret keys when secret is set, in colon format.
func ListKeysCommand(secret bool) Command {
	if secret {
		return Command{label: "List secret keys", options: append(listKeyOptions(), "--list-secret-keys")}
	}
	return Command{label: "List public keys", options: append(listKeyOptions(), "--list-keys")}
}

func listKeyOptions() []string {
	return []string{"--with-colons", "--with-fingerprint", "--with-subkey-fingerprint"}
}
